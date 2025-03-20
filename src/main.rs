mod client;
mod server;

use crate::client::run_client;
use crate::server::run_server;
use clap::{Parser, Subcommand};
use libp2p::futures::StreamExt;
use libp2p::identity::ed25519::{Keypair, PublicKey as LibP2PPublicKey, SecretKey};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};

use libp2p_proxy::client::ProxyClient;
use libp2p_proxy::server::ProxyServer;
use log::{debug, error, info};
use rand::SeedableRng;
use ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::{Ed25519PublicKey, RsaPublicKey};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use std::error::Error;
use std::fs::read_to_string;
use std::io::stdout;
use std::io::Stdout;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use ratatui::prelude::Constraint::Length;
use ratatui::{
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Direction, Layout},
    prelude::{Backend, Buffer, CrosstermBackend, Rect, StatefulWidget, Terminal, Widget},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

const RANDEVOUZE_NAMESPACE: &str = "gnostr/proxy";

const DETERMINISTIC_BYTES: [u8; 32] = [0u8; 32];

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Ssh key to run proxy with. .pub for server and private for client
    #[arg(short, long, value_name = "FILE", default_value = "~/.ssh/id_rsa")]
    key: Option<PathBuf>,

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
        #[arg(long, value_name = "LOCAL_ADDR", default_value = "0.0.0.0:0")]
        local_addr: Option<SocketAddr>,

        /// Address to connect from the server
        #[arg(long, value_name = "REMOTE_ADDR", default_value = "0.0.0.0:0")]
        remote_addr: Option<SocketAddr>,

        /// Server peer to connect
        peer_id: PeerId,
    },
}

fn get_ssh_key() -> Result<String, Box<dyn std::error::Error>> {
    let home_dir = std::env::var("HOME")?;
    let ssh_key_path = Path::new(&home_dir).join(".ssh").join("id_rsa");

    let ssh_key = fs::read_to_string(ssh_key_path)?;
    Ok(ssh_key)
}
fn get_ssh_pubkey() -> Result<String, Box<dyn std::error::Error>> {
    let home_dir = std::env::var("HOME")?;
    let ssh_key_path = Path::new(&home_dir).join(".ssh").join("id_rsa.pub");

    let ssh_key = fs::read_to_string(ssh_key_path)?;
    Ok(ssh_key)
}

fn create_peer_id_from_fixed_secret() -> Keypair {
    // A fixed, known secret key (for testing purposes ONLY).
    let seed: [u8; 32] = [
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1,
    ];

    use rand::{rngs::StdRng, RngCore, SeedableRng};

    let mut rng = StdRng::from_seed(seed);
    let mut bytes = vec![0u8; 32];
    rng.fill_bytes(&mut bytes);

    let secret_key =
        libp2p::identity::ed25519::SecretKey::from_bytes(bytes.clone()).expect("Valid secret key");
    let keypair = libp2p::identity::ed25519::Keypair::from(secret_key); //create a keypair from the secret key.
    keypair
}

fn init_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout()))
}

fn restore_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen,)
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let mut terminal = init_terminal()?;
    let restore_term = restore_terminal()?;
    let mut app = App::default();

    let keypair = create_peer_id_from_fixed_secret();

    debug!("Keypair: {:?}", keypair);

    //Accessing secret and public keys from keypair.
    let secret = keypair.secret();
    let public = keypair.public();

    debug!("Secret Key: {:?}", secret);
    debug!("Public Key: {:?}", public);

    // match get_ssh_key() {
    //     Ok(key) => {
    //         //println!("{}", key);
    //     }
    //     Err(e) => {
    //         eprintln!("Error getting SSH key: {}", e);
    //     }
    // }

    let cli = Cli::parse();

    match cli.command {
        Commands::Server => {
            if cli.key.clone().expect("cli.key.exists()").exists() {
                let key_path: PathBuf = cli.key.clone().expect("REASON");
                let key = read_to_string(key_path)?;
                // !!!! println!("{:?}", key);
                let pubkey = PublicKey::from_openssh(key.as_str())?;
                info!("{:?}", pubkey);
                run_server(pubkey).await?;
            } else {
                match get_ssh_pubkey() {
                    Ok(key) => {
                        info!("{}", key);
                        let key = PublicKey::from_openssh(key.as_str())?;
                        run_server(key).await?;
                    }
                    Err(e) => {
                        eprintln!("Error getting SSH key: {}", e);
                    }
                }
            }
        }
        Commands::Client {
            local_addr,
            remote_addr,
            peer_id,
        } => {
            if cli.key.clone().expect("cli.key.exists()").exists() {
                let key_path: PathBuf = cli.key.expect("");
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
                } else {
                    key
                };

                run_client(
                    key,
                    local_addr.expect("REASON"),
                    peer_id,
                    remote_addr.expect("REASON"),
                )
                .await?;
            } else {
                match get_ssh_key() {
                    Ok(key) => {
                        //println!("{}", key);

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
                        } else {
                            key
                        };

                        run_client(
                            key,
                            local_addr.expect("REASON"),
                            peer_id,
                            remote_addr.expect("REASON"),
                        )
                        .await?;
                    }
                    Err(e) => {
                        eprintln!("Error getting SSH key: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}
pub struct App {}
impl Default for App {
    fn default() -> Self {
        App {}
    }
}
impl App {}
