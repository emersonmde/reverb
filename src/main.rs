use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use russh::server::{Auth, Server as _, Session as ServerSession};
use russh::*;
use russh_keys::*;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    server: bool,

    #[arg(default_value = "127.0.0.1")]
    host: String,

    #[arg(long, short, default_value_t = 2222)]
    port: u16,

    // TODO: make this optional for the server
    /// Username for client
    #[arg(long, default_value = "username")]
    user: String,

    /// Path to the decrypted key file
    #[arg(long, short = 'k')]
    key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    if args.server {
        run_server(&args).await?;
    } else {
        run_client(&args).await?;
    }

    Ok(())
}

async fn run_server(args: &Args) -> Result<()> {
    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        keys: vec![russh_keys::load_secret_key(&args.key, None)?],
        ..Default::default()
    });

    let mut server = Server;

    info!("Starting server on {}:{}", args.host, args.port);
    let addr = format!("{}:{}", args.host, args.port);
    server.run_on_address(config, addr).await?;
    Ok(())
}

async fn run_client(args: &Args) -> Result<()> {
    info!("Connecting to {}:{}", args.host, args.port);
    info!("Key path: {:?}", args.key);

    let mut ssh = Session::connect(&args.key, &args.user, (args.host.clone(), args.port)).await?;
    info!("Connected");

    let data = b"foo";
    let code = ssh.send(data).await?;

    println!("Exitcode: {:?}", code);
    ssh.close().await?;
    Ok(())
}

struct Server;

impl server::Server for Server {
    type Handler = ServerHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        ServerHandler
    }
}

struct ServerHandler;

#[async_trait]
impl server::Handler for ServerHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!("Server: Received auth request for user: {}", user);
        info!("Server: Received public key: {:?}", public_key);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        session.channel_success(channel.id());
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        info!("Server: Channel {} closed by client", channel);

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let received_str = std::str::from_utf8(data)?;
        info!("Server: Received data from client: {}", received_str);

        let response = format!("Server processed: {}", received_str);
        info!("Server: Sending response to client: {}", response);

        session.data(
            channel,
            russh::CryptoVec::from(response.as_bytes().to_vec()),
        );

        Ok(())
    }
}

#[allow(dead_code)]
struct ClientHandler {
    user: String,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct Session {
    session: client::Handle<ClientHandler>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        let config = Arc::new(config);
        let user_string = user.into();
        let sh = ClientHandler {
            user: user_string.clone(),
        };

        let mut session = client::connect(config, addrs, sh).await?;
        let auth_res = session
            .authenticate_publickey(user_string, Arc::new(key_pair))
            .await?;

        if !auth_res {
            anyhow::bail!("Authentication failed");
        }

        Ok(Self { session })
    }

    async fn send(&mut self, input_data: &[u8]) -> Result<Vec<u8>> {
        let mut channel = self.session.channel_open_session().await?;

        info!("Client: Sending data to server: {:?}", input_data);
        channel.data(input_data).await?;

        let mut received_data = Vec::new();
        let mut stdout = tokio::io::stdout();

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    info!(
                        "Client: Received data from server: {:?}",
                        String::from_utf8_lossy(data)
                    );
                    stdout.write_all(data).await?;
                    stdout.flush().await?;
                    received_data.extend_from_slice(data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    info!("Client: Received exit status: {}", exit_status);
                    break;
                }
                _ => {}
            }
        }
        Ok(received_data)
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}
