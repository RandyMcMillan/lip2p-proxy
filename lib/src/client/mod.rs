mod handler;

use async_std::channel::{Receiver, SendError, Sender};
use async_std::net::{TcpListener, TcpStream};
use async_std::task::{spawn, JoinHandle};
use futures::executor::block_on;
use futures::{select, StreamExt};
use handler::{ProxyClientHandler, ProxyInClientEvent, ProxyOutClientEvent};
use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::futures::FutureExt;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    CloseConnection, ConnectionHandler, IntoConnectionHandler, NetworkBehaviour,
    NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use log::error;
use ssh_key::PrivateKey;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

struct Connection {
    listener: JoinHandle<io::Result<()>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    peer_id: PeerId,
}

#[derive(Debug)]
pub enum ProxyClientEvent {
    PeerEvent {
        peer_id: PeerId,
        event: ProxyOutClientEvent,
    },
    ListenerError(io::Error),
    ConnectionError(io::Error),
}

enum IncomingProxyClientEvent {
    // Events from user
    OpenConnection {
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        peer_id: PeerId,
    },
    CloseConnection(SocketAddr),
    Stop(PeerId),

    // Internal events
    HandlerConnected(PeerId, ConnectionId),
    HandlerEvent(ProxyClientEvent),
}

pub struct ProxyClient {
    key: PrivateKey,
    event_loop: RunningLoop,
}

impl ProxyClient {
    pub fn new(key: PrivateKey) -> Self {
        let event_loop = RunningLoop::new(key.clone());
        ProxyClient { key, event_loop }
    }

    pub fn connect(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, peer_id: PeerId) {
        let _ = self
            .event_loop
            .send_event(IncomingProxyClientEvent::OpenConnection {
                local_addr,
                remote_addr,
                peer_id,
            });
    }
}

impl NetworkBehaviour for ProxyClient {
    type ConnectionHandler = ProxyClientHandler;
    type OutEvent = ProxyClientEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        ProxyClientHandler::new(self.key.clone())
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        let _ = self
            .event_loop
            .send_event(IncomingProxyClientEvent::HandlerConnected(
                peer_id.clone(),
                connection_id.clone(),
            ));
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        _: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
        let _ = self
            .event_loop
            .send_event(IncomingProxyClientEvent::HandlerEvent(
                ProxyClientEvent::PeerEvent { peer_id, event },
            ));
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        self.event_loop.poll_event(cx)
    }
}

struct EventLoop {
    key: PrivateKey,
    connections: HashMap<PeerId, Connection>,
    handlers: HashMap<PeerId, ConnectionId>,

    event_receiver: Receiver<IncomingProxyClientEvent>,

    event_sender: Sender<NetworkBehaviourAction<ProxyClientEvent, ProxyClientHandler>>,
    connection_requested: HashSet<PeerId>,
}

async fn listen_for_connections(
    peer_id: PeerId,
    local_addr: SocketAddr,
    sender: Sender<(PeerId, TcpStream)>,
) -> io::Result<()> {
    let listener = TcpListener::bind(local_addr).await?;
    loop {
        let con = listener.accept().await?;
        let _ = sender.send((peer_id, con.0)).await;
    }
}

struct RunningLoop {
    local_event_sender: Sender<IncomingProxyClientEvent>,
    local_event_receiver: Receiver<NetworkBehaviourAction<ProxyClientEvent, ProxyClientHandler>>,
    running_loop: JoinHandle<()>,
}

impl RunningLoop {
    fn new(key: PrivateKey) -> Self {
        let (local_event_sender, event_receiver) = async_std::channel::unbounded();
        let (event_sender, local_event_receiver) = async_std::channel::unbounded();

        let event_loop = EventLoop {
            key,
            connections: Default::default(),
            handlers: Default::default(),
            event_receiver,
            event_sender,
            connection_requested: Default::default(),
        };

        let running_loop = spawn(event_loop.run());

        RunningLoop {
            local_event_sender,
            local_event_receiver,
            running_loop,
        }
    }

    fn send_event(
        &self,
        event: IncomingProxyClientEvent,
    ) -> Result<(), SendError<IncomingProxyClientEvent>> {
        block_on(self.local_event_sender.send(event))
    }

    fn poll_event(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<NetworkBehaviourAction<ProxyClientEvent, ProxyClientHandler>> {
        let poll = self.local_event_receiver.poll_next_unpin(cx);

        match poll {
            Poll::Ready(op) => match op {
                None => {
                    unimplemented!()
                }
                Some(e) => Poll::Ready(e),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl EventLoop {
    async fn process_event(
        &mut self,
        event: IncomingProxyClientEvent,
        sender: Sender<(PeerId, TcpStream)>,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            IncomingProxyClientEvent::OpenConnection {
                local_addr,
                remote_addr,
                peer_id,
            } => {
                let f = spawn(listen_for_connections(
                    peer_id.clone(),
                    local_addr.clone(),
                    sender.clone(),
                ));
                let con = Connection {
                    listener: f,
                    local_addr,
                    remote_addr,
                    peer_id,
                };
                self.connections.insert(peer_id, con);
            }
            IncomingProxyClientEvent::CloseConnection(_) => {
                unimplemented!()
            }
            IncomingProxyClientEvent::Stop(peer_id) => {
                if let Some(con) = self.handlers.remove(&peer_id) {
                    self.event_sender
                        .send(NetworkBehaviourAction::CloseConnection {
                            peer_id,
                            connection: CloseConnection::One(con.clone()),
                        })
                        .await?;
                }
                // TODO close acceptors
            }

            IncomingProxyClientEvent::HandlerConnected(peer_id, connection_id) => {
                self.handlers.insert(peer_id, connection_id);
            }

            IncomingProxyClientEvent::HandlerEvent(e) => {
                let _ = self
                    .event_sender
                    .send(NetworkBehaviourAction::GenerateEvent(e))
                    .await;
            }
        }
        Ok(())
    }

    async fn run(mut self) {
        let (sender, receiver) = async_std::channel::unbounded();
        let mut pending_streams: VecDeque<(PeerId, TcpStream)> = VecDeque::new();

        loop {
            let mut event_selector = self.event_receiver.recv().fuse();
            let mut con_selector = receiver.recv().fuse();
            if let Some((peer_id, stream)) = pending_streams.pop_front() {
                if let Some(connection_id) = self.handlers.get(&peer_id) {
                    let _ = self
                        .event_sender
                        .send(NetworkBehaviourAction::NotifyHandler {
                            peer_id,
                            handler: NotifyHandler::One(connection_id.clone()),
                            event: ProxyInClientEvent::Connect {
                                addr: self.connections.get(&peer_id).unwrap().remote_addr,
                                stream,
                            },
                        })
                        .await;
                }
            }
            select! {
                event = event_selector => {
                    match event {
                        Ok(event) => {
                            let res = self.process_event(event, sender.clone()).await;
                            if let Err(err) = res {
                                error!("Error while processing event: {err}");
                            }
                        }
                        Err(err) => {
                            error!("Error in event loop {err}, stopping it");
                            return;
                        }
                    }
                }

                con = con_selector => {
                    match con {
                        Ok(con) => {
                            pending_streams.push_back(con);
                        }
                        Err(err) => {
                            error!("Error in event loop {err}, stopping it");
                            return;
                        }
                    }
                }

            }
        }
    }
}
