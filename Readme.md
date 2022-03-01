To run from project: </br>
Install Rust and Cargo with rustup </br>
Set all configs in files below </br>
Run "cargo run" 

Config ("config" file): </br>
execution_time {seconds} (default 60) </br>
timeout {milliseconds} (time for the thread t sleep between each attack) (default 10) </br>
packet_size {bytes} (default 65000) </br>
default_ports {number, ...} (default port(s) (at least 1) if none included) (mandatory) </br>
unreachable_stop_trying {true/false} (case insensitive) (default true)

Websites ("webistes" file): </br>
If ip address: </br>
ip {address} [port]
</br>

If domain: </br>
domain {domain} [port1, port2] </br>

Examples: </br>
ip 127.0.0.1 </br> 
ip 127.0.0.1 80 </br>
ip 127.0.0.1 80 443 </br>
domain website.com </br>
domain website.com 80 </br>
domain website.com 80 443 </br>