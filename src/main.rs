mod client;
mod server;

use std::{env, io};
use std::error::Error;
use std::fs::read_to_string;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use libp2p::{Multiaddr, PeerId, Swarm};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use rand::SeedableRng;
use ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use libp2p_proxy::client::ProxyClient;
use libp2p_proxy::server::ProxyServer;
use clap::{Parser, Subcommand};
use log::{debug, error};
use ssh_key::public::{Ed25519PublicKey, RsaPublicKey};
use crate::client::run_client;
use crate::server::run_server;

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

const RANDEVOUZE_NAMESPACE: &str = "tricker/proxy";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Ssh key to run proxy with. .pub for server and private for client
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a proxy server
    Server,

    /// Start proxy client
    Client {

        /// Address to start proxy
        local_addr: SocketAddr,

        /// Address to connect from the server
        remote_addr: SocketAddr,

        /// Server peer to connect
        peer_id: PeerId
    }
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Server => {
            let key_path: PathBuf = cli.key;
            let key = read_to_string(key_path)?;
            let key = PublicKey::from_openssh(key.as_str())?;
            run_server(key).await?;
        }
        Commands::Client {
            local_addr, remote_addr, peer_id
        } => {
            let key_path: PathBuf = cli.key;
            let key = read_to_string(key_path)?;
            let key = PrivateKey::from_openssh(key.as_str())?;

            let key = if key.is_encrypted() {
                let mut str = String::new();
                print!("passphrase: ");
                io::stdout().flush()?;
                io::stdin().read_line(&mut str)?;
                let res = key.decrypt(str);
                if let Err(err) = res {
                    error!("Cannot decrypt key: {err}");
                }
                res?
            } else { key };

            run_client(key, local_addr, peer_id, remote_addr).await?;
        }
    }
    Ok(())
}
