To run from project: </br>
Install Rust and Cargo with rustup </br>
Set all configs in files below </br>
Run "cargo run"

Both configuration lines support comments (but checks at the start of the line for now) with "//"

Config ("config" file): </br>
execution_time {seconds} (default 60) </br>
timeout {milliseconds} (time for the thread t sleep between each attack) (default 10) </br>
packet_size {bytes} (default 65000) </br>
default_ports {number, ...} (default port(s) (at least 1) if none included) (mandatory) </br>
unreachable_stop_trying {true/false} (case insensitive) (default true)
default_attack_methods {attack_method, ...} (case insensitive) (default attack method(s) (at least 1) if none included) (mandatory) </br>
tcp_connection_timeout {seconds} (the amount of time allowed to create tcp connection) (default 5)

Websites ("webistes" file): </br>
If ip address: </br>
ip {address} [attack_method1, attack_method2] [port1, port2]
</br>

If domain: </br>
domain {domain} [attack_method1, attack_method2] [port1, port2] </br>

Examples: </br>
ip 127.0.0.1 </br> 
ip 127.0.0.1 udp </br> 
ip 127.0.0.1 udp tcp </br> 
ip 127.0.0.1 80 </br>
ip 127.0.0.1 udp 80 </br>
ip 127.0.0.1 udp tcp 80 </br>
ip 127.0.0.1 80 443 </br>
ip 127.0.0.1 udp 80 443 </br>
ip 127.0.0.1 udp tcp 80 443 </br>
domain website.com </br>
domain website.com udp </br>
domain website.com udp tcp </br>
domain website.com 80 </br>
domain website.com udp 80 </br>
domain website.com udp tcp 80 </br>
domain website.com 80 443 </br>
domain website.com udp tcp 80 443 </br>
domain website.com udp tcp 80 443 </br>