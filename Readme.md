To run from project:
Install Rust and Cargo with rustup
Set all configs in files below
Run "cargo run"

Config ("config" file):
execution_time {seconds}
timeout {milliseconds} (time for the thread t sleep between each attack)
packet_size {bytes}
port {number}

Websites ("webistes" file):
If ip address:
ip {address} {port}

If domain:
domain {domain}