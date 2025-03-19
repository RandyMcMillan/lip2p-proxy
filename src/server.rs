use crate::{Multiaddr, SwarmEvent, BOOTNODES};
use async_std::task::block_on;
use futures::StreamExt;
use libp2p::core::transport::{upgrade, OrTransport};
use libp2p::dns::GenDnsConfig;
use libp2p::gossipsub::TopicHash;
use libp2p::gossipsub::{
    Gossipsub, GossipsubConfig, GossipsubConfigBuilder, GossipsubEvent, MessageAuthenticity,
};
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{GetClosestPeersError, Kademlia, KademliaConfig, KademliaEvent, QueryResult};
use libp2p::multiaddr::Protocol;
use libp2p::ping::{Ping, PingEvent};
use libp2p::relay::v2::HOP_PROTOCOL_NAME;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::AddressRecord;
use libp2p::tcp::GenTcpConfig;
use libp2p::{
    autonat, development_transport, gossipsub, identity, noise, relay, NetworkBehaviour, PeerId,
    Swarm, Transport,
};
use libp2p_dns::DnsConfig;
use libp2p_proxy::client::{ProxyClient, ProxyClientEvent};
use libp2p_proxy::server::ProxyServer;
use libp2p_tcp::TcpTransport;
use log::{debug, error, info};
use ssh_key::{PrivateKey, PublicKey};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::ops::Sub;
use std::str::FromStr;
use std::time::{Duration, Instant};

const MAX_RELAYS: usize = 5;
const MAX_PEERS: usize = 25;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ServerEvent")]
struct ServerBehaviour {
    kadmelia: Kademlia<MemoryStore>,
    identify: Identify,
    server: ProxyServer,
    ping: Ping,
    auto_nat: autonat::Behaviour,
    relay: relay::v2::client::Client,
}

#[derive(Debug)]
enum ServerEvent {
    Server(()),
    Kadmelia(KademliaEvent),
    Identify(IdentifyEvent),
    Ping(PingEvent),
    AutoNat(autonat::Event),
    Relay(relay::v2::client::Event),
}

impl From<KademliaEvent> for ServerEvent {
    fn from(e: KademliaEvent) -> Self {
        Self::Kadmelia(e)
    }
}

impl From<()> for ServerEvent {
    fn from(_: ()) -> Self {
        Self::Server(())
    }
}

impl From<IdentifyEvent> for ServerEvent {
    fn from(e: IdentifyEvent) -> Self {
        Self::Identify(e)
    }
}

impl From<PingEvent> for ServerEvent {
    fn from(e: PingEvent) -> Self {
        Self::Ping(e)
    }
}

impl From<autonat::Event> for ServerEvent {
    fn from(e: autonat::Event) -> Self {
        Self::AutoNat(e)
    }
}

impl From<relay::v2::client::Event> for ServerEvent {
    fn from(e: relay::v2::client::Event) -> Self {
        Self::Relay(e)
    }
}

pub async fn run_server(key: PublicKey) -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    info!("Peer id is {local_peer_id}");

    let (relay_transport, client) =
        relay::v2::client::Client::new_transport_and_behaviour(local_peer_id);

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&local_key)
        .expect("Signing libp2p-noise static DH keypair failed.");

    let transport = OrTransport::new(
        relay_transport,
        block_on(DnsConfig::system(TcpTransport::new(
            GenTcpConfig::default().port_reuse(true),
        )))
        .unwrap(),
    )
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
    .multiplex(libp2p::yamux::YamuxConfig::default())
    .boxed();

    let mut swarm = {
        let mut cfg = KademliaConfig::default();
        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        let store = MemoryStore::new(local_peer_id);
        let mut kadmelia = Kademlia::with_config(local_peer_id, store, cfg);

        let mut behaviour = ServerBehaviour {
            server: ProxyServer::new(key),
            kadmelia,
            identify: Identify::new(IdentifyConfig::new(
                "/ipfs/0.1.0".into(),
                local_key.public(),
            )),
            ping: Ping::default(),
            auto_nat: autonat::Behaviour::new(
                local_peer_id,
                autonat::Config {
                    retry_interval: Duration::from_secs(10),
                    refresh_interval: Duration::from_secs(30),
                    boot_delay: Duration::from_secs(5),
                    throttle_server_period: Duration::ZERO,
                    ..Default::default()
                },
            ),
            relay: client,
        };

        let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;

        for peer in &BOOTNODES {
            behaviour
                .kadmelia
                .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
        }

        Swarm::new(transport, behaviour, local_peer_id)
    };

    swarm.behaviour_mut().kadmelia.bootstrap()?;
    let mut relays_map = HashMap::new();
    let mut pending_relay_listeners = HashSet::new();

    loop {
        let event = swarm.select_next_some().await;
        match event {
            SwarmEvent::Behaviour(e) => {
                match e {
                    ServerEvent::Relay(relay::v2::client::Event::ReservationReqAccepted {
                        relay_peer_id,
                        ..
                    }) => {
                        info!("Reserved address on relay {:#?}", relay_peer_id);
                    }

                    ServerEvent::Relay(relay::v2::client::Event::ReservationReqFailed {
                        relay_peer_id,
                        error,
                        ..
                    }) => {
                        info!(
                            "Failed to reserve address on relay {:#?}: {:#?}",
                            relay_peer_id, error
                        );
                    }

                    ServerEvent::Identify(IdentifyEvent::Received { peer_id, info }) => {
                        if relays_map.len() < MAX_RELAYS
                            && pending_relay_listeners.len() < MAX_RELAYS
                            && info
                                .protocols
                                .contains(&String::from_utf8_lossy(HOP_PROTOCOL_NAME).to_string())
                        {
                            info!("Trying to set peer {peer_id} as relay");
                            let addr = Multiaddr::empty()
                                .with(Protocol::Memory(40))
                                .with(Protocol::P2p(peer_id.into()))
                                .with(Protocol::P2pCircuit);
                            let res = swarm.listen_on(addr);
                            if let Err(e) = res {
                                error!("Error while connecting to relay: {:#?}", e);
                            } else {
                                pending_relay_listeners.insert(res.unwrap());
                            }
                        }

                        if info.protocols.contains(&"/rendezvous/1.0.0".to_string()) {
                            info!("Found rendezvous point {peer_id}");
                        }
                    }
                    _ => {}
                };
            }

            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                println!("Listening on {address}");
                pending_relay_listeners.remove(&listener_id);
                relays_map.insert(listener_id, address);
            }

            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                ..
            } => {
                info!("Stopping listening on {:?}", addresses);
                relays_map.remove(&listener_id);
            }

            _ => {}
        }
    }
}
