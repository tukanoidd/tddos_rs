To run from project: </br>
Install Rust and Cargo with rustup </br>
Set all configs in files below </br>
Run "cargo run" 

Config ("config" file): </br>
execution_time {seconds} </br>
timeout {milliseconds} (time for the thread t sleep between each attack) </br>
packet_size {bytes} </br>
default_port {number} (default port if none included) </br>

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