use std::task::{Context, Poll};
use libp2p::core::connection::ConnectionId;
use libp2p::PeerId;
use libp2p::swarm::{ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters};
use ssh_key::PublicKey;
use crate::server::ProxyServerHandler;

pub struct ProxyServer {
    pub(crate) key: PublicKey
}

impl NetworkBehaviour for ProxyServer {
    type ConnectionHandler = ProxyServerHandler;
    type OutEvent = ();

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        ProxyServerHandler::new(self.key.clone())
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent) {}

    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl PollParameters) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        Poll::Pending
    }
}