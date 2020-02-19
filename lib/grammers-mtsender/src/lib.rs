// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
mod errors;
mod tcp_transport;

pub use errors::{AuthorizationError, InvocationError};
use tcp_transport::TcpTransport;

use futures::channel::{mpsc, oneshot};
use futures::future::{self, Either};
use futures::{SinkExt, StreamExt};
use grammers_crypto::{auth_key, AuthKey};
use grammers_mtproto::errors::RequestError;
use grammers_mtproto::transports::TransportFull;
use grammers_mtproto::MTProto;
pub use grammers_mtproto::DEFAULT_COMPRESSION_THRESHOLD;
use grammers_tl_types::{Deserializable, RPC};

use std::io;
use std::net::ToSocketAddrs;

struct Request {
    payload: Vec<u8>,
    writeback: oneshot::Sender<Result<Vec<u8>, InvocationError>>,
}

/// A builder to configure `MTSender` instances.
pub struct MTSenderBuilder {
    compression_threshold: Option<usize>,
    auth_key: Option<AuthKey>,
}

/// A Mobile Transport sender, using the [Mobile Transport Protocol]
/// underneath.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto
pub struct MTSender {
    sender: mpsc::UnboundedSender<Request>,
}

impl MTSenderBuilder {
    fn new() -> Self {
        Self {
            compression_threshold: DEFAULT_COMPRESSION_THRESHOLD,
            auth_key: None,
        }
    }

    /// Configures the compression threshold for outgoing messages.
    pub fn compression_threshold(mut self, threshold: Option<usize>) -> Self {
        self.compression_threshold = threshold;
        self
    }

    /// Sets the authorization key to be used. Otherwise, no authorization
    /// key will be present, and a new one will have to be generated before
    /// being able to send encrypted messages.
    pub fn auth_key(mut self, auth_key: AuthKey) -> Self {
        self.auth_key = Some(auth_key);
        self
    }

    /// Finishes the builder and returns the `MTProto` instance with all
    /// the configuration changes applied.
    pub async fn connect<A: ToSocketAddrs>(self, addr: A) -> io::Result<MTSender> {
        MTSender::with_builder(self, addr).await
    }
}

impl MTSender {
    /// Returns a builder to configure certain parameters.
    pub fn build() -> MTSenderBuilder {
        MTSenderBuilder::new()
    }

    /// Creates and connects a new instance with default settings.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Self::build().connect(addr).await
    }

    /// Constructs an instance using a finished builder.
    ///
    /// If no authorization key is provided, a new one will be generated.
    async fn with_builder<A: ToSocketAddrs>(builder: MTSenderBuilder, addr: A) -> io::Result<Self> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let transport = TcpTransport::connect(addr).await?;

        let mut protocol = MTProto::build().compression_threshold(builder.compression_threshold);

        if let Some(auth_key) = builder.auth_key {
            protocol = protocol.auth_key(auth_key);
        } else {
            // TODO this design doesn't feel right e.g. now we can't
            //      generate a new authkey without creating a new sender,
            //      and free-standing functions feel out of place
            generate_auth_key(&mut protocol, &mut transport);
        }

        let protocol = protocol.finish();

        let (tx, rx) = mpsc::unbounded::<Request>();

        //tokio::spawn(process_responses(transport, rx));
        network_loop(transport, rx).await;

        Ok(Self {
            protocol,
            sender: tx,
        })
    }

    /// Invokes a request. The call will complete once a response
    /// arrives, which means the sender's main loop must be running.
    pub async fn invoke<R: RPC>(&mut self, request: &R) -> Result<R::Return, InvocationError> {
        todo!()
    }

    async fn send(&self, payload: Vec<u8>) -> Result<Vec<u8>, InvocationError> {
        // TODO proper error
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Request {
                payload,
                writeback: tx,
            })
            .await
            .unwrap();
        rx.await
    }

    /// Block invoking a single Remote Procedure Call and return its result.
    ///
    /// The invocation might fail due to network problems, in which case the
    /// outermost result represents failure.
    ///
    /// If the request is both sent and received successfully, then the
    /// request itself was understood by the server, but it could not be
    /// executed. This is represented by the innermost result.
    pub async fn old_invoke<R: RPC>(&mut self, request: &R) -> Result<R::Return, InvocationError> {
        let mut msg_id = self.protocol.enqueue_request(request.to_bytes())?;
        loop {
            // The protocol may generate more outgoing requests, so we need
            // to constantly check for those until we receive a response.
            while let Some(payload) = self.protocol.serialize_encrypted_messages()? {
            }

            // Process all messages we receive.
            let response = Vec::new();
            self.protocol.process_encrypted_response(&response)?;

            // TODO dispatch this somehow
            while let Some(data) = self.protocol.poll_update() {
                eprintln!("Received update data: {:?}", data);
            }

            // See if there are responses to our request.
            while let Some((response_id, data)) = self.protocol.poll_response() {
                if response_id == msg_id {
                    match data {
                        Ok(x) => {
                            return Ok(R::Return::from_bytes(&x)?);
                        }
                        Err(RequestError::RPCError(error)) => {
                            return Err(InvocationError::RPC(error));
                        }
                        Err(RequestError::Dropped) => {
                            return Err(InvocationError::Dropped);
                        }
                        Err(RequestError::BadMessage { .. }) => {
                            // Need to retransmit
                            msg_id = self.protocol.enqueue_request(request.to_bytes())?;
                        }
                    }
                }
            }
        }
    }

}

/// Performs the handshake necessary to generate a new authorization
/// key that can be used to safely transmit data to and from the server.
///
/// See also: https://core.telegram.org/mtproto/auth_key.
pub async fn generate_auth_key(protocol: &mut MTProto, transport: &mut TcpTransport<TransportFull>) -> Result<AuthKey, AuthorizationError> {
    let (request, data) = auth_key::generation::step1()?;
    let response = invoke_plain_request(protocol, transport, &request).await?;

    let (request, data) = auth_key::generation::step2(data, response)?;
    let response = invoke_plain_request(protocol, transport, &request).await?;

    let (request, data) = auth_key::generation::step3(data, response)?;
    let response = invoke_plain_request(protocol, transport, &request).await?;

    let (auth_key, time_offset) = auth_key::generation::create_key(data, response)?;
    protocol.set_auth_key(auth_key.clone(), time_offset);

    Ok(auth_key)
}

/// Invoke a serialized request in plaintext.
async fn invoke_plain_request(protocol: &mut MTProto, transport: &mut TcpTransport<TransportFull>, request: &[u8]) -> Result<Vec<u8>, InvocationError> {
    let payload = protocol.serialize_plain_message(request);
    transport.send(&payload).await?;

    let response = receive_message(transport).await?;
    protocol
        .deserialize_plain_message(&response)
        .map(|x| x.to_vec())
        .map_err(InvocationError::from)
}

/// Receives a single message from the server
async fn receive_message(transport: &mut TcpTransport<TransportFull>) -> Result<Vec<u8>, io::Error> {
    transport.recv().await.map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => io::Error::new(io::ErrorKind::ConnectionReset, e),
        _ => e,
    })
}

// TODO let the user change the type of transport used
async fn network_loop(
    transport: TcpTransport<TransportFull>,
    requests: mpsc::UnboundedReceiver<Request>,
    protocol: MTProto,
) {
    // TODO uhh i guess our TcpTransport needs some .split().......
    //      and both sides will need to keep some state. this is eeky

    // Incoming requests or incoming responses, whatever happens first
    future::select(requests, future2: B)

    transport.recv().await.map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => io::Error::new(io::ErrorKind::ConnectionReset, e),
        _ => e,
    });

    // Something happened (new requests or new response), try and see if
    // we have things to send.
    while let Ok(Some(payload)) = protocol.serialize_encrypted_messages() {
        // TODO handle errors
        // Sending payload or incoming responses, whatever happens first
        transport.send(&payload).await;
    }


    /*

async fn process_responses(incoming_requests: MsgReceiver) {
    // First lets connect to the server and split our stream into read and write
    let mut stream = TcpStream::connect("127.0.0.1:7878").await.unwrap();
    let (read_stream, write_stream) = stream.split();

    // Lets take that write stream and pass it to a SerealSink which will take in Messages
    // and serialize them to send them down the tcp sink
    let mut server_sink = SerealSink::new(write_stream);

    // Now lets take that read stream, and pass it to a SerealStreamer which will read input
    // from the stream and deserialize it into Messages.
    // We map these messages to the Input enum
    let results_stream = SerealStreamer::new(read_stream).map(Input::Result);

    // Now lets take the incoming requests stream and wrap them in the Input enum too.
    let requests_stream = incoming_requests.map(Input::Request);

    // This finally allows us to merge the two streams so that we're awaiting a message from either.
    // This way, we can receive a request from the client, or a result from the server immediately
    // as either happen.
    let mut combined_stream = futures::stream::select(results_stream, requests_stream);

    // We also need a way to route each incoming result back to the request it came from. Luckily
    // Each message has a u32 id associated with it. So we create a hashmap of the ids and oneshot
    // senders that we will use to send back the result in.
    let mut request_map: HashMap<u32, oneshot::Sender<MathResult>> = HashMap::new();

    // Now we're ready to receive results or requests from our stream.
    while let Some(input) = combined_stream.next().await {
        match input {
            // We've received a request from the client
            Input::Request((req, tx)) => {
                println!("{:?}", req);
                // Let's send the request to the server through the SerealSink
                server_sink.send(&req).await.unwrap();
                // And lets put that request id into the map so we can send the result back
                request_map.insert(req.id, tx);
            }

            // We've received a result from the server
            Input::Result(result) => {
                println!("{:?}", result);
                // Get the oneshot sender from the map that matches with the id
                let tx = request_map.remove(&result.id).unwrap();
                // Send the result back to the client
                tx.send(result).unwrap();
            }
        }
    }
}
     */
}
