# if-addrs
https://crates.io/crates/if-addrs

## Overview

Retrieve network interface info for all interfaces on the system:

```rust
// List all of the machine's network interfaces
for iface in if_addrs::get_if_addrs().unwrap() {
    println!("{:#?}", iface);
}
```

Each `Interface` includes its IP address, index, operational status, whether it
is point-to-point, and its hardware (MAC) address when available:

```rust
for iface in if_addrs::get_if_addrs().unwrap() {
    if let Some(mac) = iface.mac_addr() {
        println!("{}: {}", iface.name, mac); // e.g. "eth0: 02:fc:00:00:00:01"
    }
}
```

The MAC address is read from the same OS interface-enumeration call used for the
IP information (`getifaddrs` link-layer entries on POSIX, `GetAdaptersAddresses`
on Windows), so it stays cross-platform without reaching into `/sys` or other
platform-specific locations.

Get notifications for changes in network interfaces:

```rust
let mut notifier = if_addrs::IfChangeNotifier::new().unwrap();
loop {
    if let Ok(details) = notifier.wait(None) {
        println!("{:#?}", details);
    }
}
```

## License

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) http://opensource.org/licenses/MIT) at your option.

## Contribution

Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.
