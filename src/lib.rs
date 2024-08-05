// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(windows))]
mod posix;
#[cfg(all(
    not(windows),
    not(all(
        target_vendor = "apple",
        any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )
    ))
))]
mod posix_not_apple;
mod sockaddr;
#[cfg(windows)]
mod windows;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Details about an interface on this host.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// The address details of the interface.
    pub addr: IfAddr,
    /// The index of the interface.
    pub index: Option<u32>,
    /// (Windows only) A permanent and unique identifier for the interface. It
    /// cannot be modified by the user. It is typically a GUID string of the
    /// form: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", but this is not
    /// guaranteed by the Windows API.
    #[cfg(windows)]
    pub adapter_name: String,
}

impl Interface {
    /// Check whether this is a loopback interface.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }

    /// Check whether this is a link local interface.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        self.addr.is_link_local()
    }

    /// Get the IP address of this interface.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.addr.ip()
    }
}

/// Details about the address of an interface on this host.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum IfAddr {
    /// This is an Ipv4 interface.
    V4(Ifv4Addr),
    /// This is an Ipv6 interface.
    V6(Ifv6Addr),
}

impl IfAddr {
    /// Check whether this is a loopback address.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        match *self {
            IfAddr::V4(ref ifv4_addr) => ifv4_addr.is_loopback(),
            IfAddr::V6(ref ifv6_addr) => ifv6_addr.is_loopback(),
        }
    }

    /// Check whether this is a link local interface.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        match *self {
            IfAddr::V4(ref ifv4_addr) => ifv4_addr.is_link_local(),
            IfAddr::V6(ref ifv6_addr) => ifv6_addr.is_link_local(),
        }
    }

    /// Get the IP address of this interface address.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        match *self {
            IfAddr::V4(ref ifv4_addr) => IpAddr::V4(ifv4_addr.ip),
            IfAddr::V6(ref ifv6_addr) => IpAddr::V6(ifv6_addr.ip),
        }
    }
}

/// Details about the ipv4 address of an interface on this host.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ifv4Addr {
    /// The IP address of the interface.
    pub ip: Ipv4Addr,
    /// The netmask of the interface.
    pub netmask: Ipv4Addr,
    /// The CIDR prefix of the interface.
    pub prefixlen: u8,
    /// The broadcast address of the interface.
    pub broadcast: Option<Ipv4Addr>,
}

impl Ifv4Addr {
    /// Check whether this is a loopback address.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.ip.is_loopback()
    }

    /// Check whether this is a link local address.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        self.ip.is_link_local()
    }
}

/// Details about the ipv6 address of an interface on this host.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Ifv6Addr {
    /// The IP address of the interface.
    pub ip: Ipv6Addr,
    /// The netmask of the interface.
    pub netmask: Ipv6Addr,
    /// The CIDR prefix of the interface.
    pub prefixlen: u8,
    /// The broadcast address of the interface.
    pub broadcast: Option<Ipv6Addr>,
}

impl Ifv6Addr {
    /// Check whether this is a loopback address.
    #[must_use]
    pub const fn is_loopback(&self) -> bool {
        self.ip.is_loopback()
    }

    /// Check whether this is a link local address.
    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        let bytes = self.ip.octets();

        bytes[0] == 0xfe && bytes[1] == 0x80
    }
}

#[cfg(not(windows))]
mod getifaddrs_posix {
    use libc::if_nametoindex;

    use super::{IfAddr, Ifv4Addr, Ifv6Addr, Interface};
    use crate::posix::{self as ifaddrs, IfAddrs};
    use crate::sockaddr;
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Return a vector of IP details for all the valid interfaces on this host.
    #[allow(unsafe_code)]
    pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
        let mut ret = Vec::<Interface>::new();
        let ifaddrs = IfAddrs::new()?;

        for ifaddr in ifaddrs.iter() {
            let addr = match sockaddr::to_ipaddr(ifaddr.ifa_addr) {
                None => continue,
                Some(IpAddr::V4(ipv4_addr)) => {
                    let netmask = match sockaddr::to_ipaddr(ifaddr.ifa_netmask) {
                        Some(IpAddr::V4(netmask)) => netmask,
                        _ => Ipv4Addr::new(0, 0, 0, 0),
                    };
                    let broadcast = if (ifaddr.ifa_flags & 2) != 0 {
                        match ifaddrs::do_broadcast(&ifaddr) {
                            Some(IpAddr::V4(broadcast)) => Some(broadcast),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let prefixlen = if cfg!(target_endian = "little") {
                        u32::from_le_bytes(netmask.octets()).count_ones() as u8
                    } else {
                        u32::from_be_bytes(netmask.octets()).count_ones() as u8
                    };
                    IfAddr::V4(Ifv4Addr {
                        ip: ipv4_addr,
                        netmask,
                        prefixlen,
                        broadcast,
                    })
                }
                Some(IpAddr::V6(ipv6_addr)) => {
                    let netmask = match sockaddr::to_ipaddr(ifaddr.ifa_netmask) {
                        Some(IpAddr::V6(netmask)) => netmask,
                        _ => Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    };
                    let broadcast = if (ifaddr.ifa_flags & 2) != 0 {
                        match ifaddrs::do_broadcast(&ifaddr) {
                            Some(IpAddr::V6(broadcast)) => Some(broadcast),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let prefixlen = if cfg!(target_endian = "little") {
                        u128::from_le_bytes(netmask.octets()).count_ones() as u8
                    } else {
                        u128::from_be_bytes(netmask.octets()).count_ones() as u8
                    };
                    IfAddr::V6(Ifv6Addr {
                        ip: ipv6_addr,
                        netmask,
                        prefixlen,
                        broadcast,
                    })
                }
            };

            let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let index = {
                let index = unsafe { if_nametoindex(ifaddr.ifa_name) };

                // From `man if_nametoindex 3`:
                // The if_nametoindex() function maps the interface name specified in ifname to its
                // corresponding index. If the specified interface does not exist, it returns 0.
                if index == 0 {
                    None
                } else {
                    Some(index)
                }
            };
            ret.push(Interface { name, addr, index });
        }

        Ok(ret)
    }
}

/// Get a list of all the network interfaces on this machine along with their IP info.
#[cfg(not(windows))]
pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
    getifaddrs_posix::get_if_addrs()
}

#[cfg(windows)]
mod getifaddrs_windows {
    use super::{IfAddr, Ifv4Addr, Ifv6Addr, Interface};
    use crate::sockaddr;
    use crate::windows::IfAddrs;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::IpDadStatePreferred;

    /// Return a vector of IP details for all the valid interfaces on this host.
    pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
        let mut ret = Vec::<Interface>::new();
        let ifaddrs = IfAddrs::new()?;

        for ifaddr in ifaddrs.iter() {
            for addr in ifaddr.unicast_addresses() {
                if addr.DadState != IpDadStatePreferred {
                    continue;
                }
                let addr = match sockaddr::to_ipaddr(addr.Address.lpSockaddr) {
                    None => continue,
                    Some(IpAddr::V4(ipv4_addr)) => {
                        let mut item_netmask = Ipv4Addr::new(0, 0, 0, 0);
                        let mut item_broadcast = None;
                        let item_prefix = addr.OnLinkPrefixLength;

                        // Search prefixes for a prefix matching addr
                        'prefixloopv4: for prefix in ifaddr.prefixes() {
                            let ipprefix = sockaddr::to_ipaddr(prefix.Address.lpSockaddr);
                            match ipprefix {
                                Some(IpAddr::V4(ref a)) => {
                                    let mut netmask: [u8; 4] = [0; 4];
                                    for (n, netmask_elt) in netmask
                                        .iter_mut()
                                        .enumerate()
                                        .take((prefix.PrefixLength as usize + 7) / 8)
                                    {
                                        let x_byte = ipv4_addr.octets()[n];
                                        let y_byte = a.octets()[n];
                                        for m in 0..8 {
                                            if (n * 8) + m > prefix.PrefixLength as usize {
                                                break;
                                            }
                                            let bit = 1 << (7 - m);
                                            if (x_byte & bit) == (y_byte & bit) {
                                                *netmask_elt |= bit;
                                            } else {
                                                continue 'prefixloopv4;
                                            }
                                        }
                                    }
                                    item_netmask = Ipv4Addr::new(
                                        netmask[0], netmask[1], netmask[2], netmask[3],
                                    );
                                    let mut broadcast: [u8; 4] = ipv4_addr.octets();
                                    for n in 0..4 {
                                        broadcast[n] |= !netmask[n];
                                    }
                                    item_broadcast = Some(Ipv4Addr::new(
                                        broadcast[0],
                                        broadcast[1],
                                        broadcast[2],
                                        broadcast[3],
                                    ));
                                    break 'prefixloopv4;
                                }
                                _ => continue,
                            };
                        }
                        IfAddr::V4(Ifv4Addr {
                            ip: ipv4_addr,
                            netmask: item_netmask,
                            prefixlen: item_prefix,
                            broadcast: item_broadcast,
                        })
                    }
                    Some(IpAddr::V6(ipv6_addr)) => {
                        let mut item_netmask = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
                        let item_prefix = addr.OnLinkPrefixLength;
                        // Search prefixes for a prefix matching addr
                        'prefixloopv6: for prefix in ifaddr.prefixes() {
                            let ipprefix = sockaddr::to_ipaddr(prefix.Address.lpSockaddr);
                            match ipprefix {
                                Some(IpAddr::V6(ref a)) => {
                                    // Iterate the bits in the prefix, if they all match this prefix
                                    // is the right one, else try the next prefix
                                    let mut netmask: [u16; 8] = [0; 8];
                                    for (n, netmask_elt) in netmask
                                        .iter_mut()
                                        .enumerate()
                                        .take((prefix.PrefixLength as usize + 15) / 16)
                                    {
                                        let x_word = ipv6_addr.segments()[n];
                                        let y_word = a.segments()[n];
                                        for m in 0..16 {
                                            if (n * 16) + m > prefix.PrefixLength as usize {
                                                break;
                                            }
                                            let bit = 1 << (15 - m);
                                            if (x_word & bit) == (y_word & bit) {
                                                *netmask_elt |= bit;
                                            } else {
                                                continue 'prefixloopv6;
                                            }
                                        }
                                    }
                                    item_netmask = Ipv6Addr::new(
                                        netmask[0], netmask[1], netmask[2], netmask[3], netmask[4],
                                        netmask[5], netmask[6], netmask[7],
                                    );
                                    break 'prefixloopv6;
                                }
                                _ => continue,
                            };
                        }
                        IfAddr::V6(Ifv6Addr {
                            ip: ipv6_addr,
                            netmask: item_netmask,
                            prefixlen: item_prefix,
                            broadcast: None,
                        })
                    }
                };

                let index = match addr {
                    IfAddr::V4(_) => ifaddr.ipv4_index(),
                    IfAddr::V6(_) => ifaddr.ipv6_index(),
                };
                ret.push(Interface {
                    name: ifaddr.name(),
                    addr,
                    index,
                    adapter_name: ifaddr.adapter_name(),
                });
            }
        }

        Ok(ret)
    }
}

/// Get a list of all the network interfaces on this machine along with their IP info.
#[cfg(windows)]
pub fn get_if_addrs() -> io::Result<Vec<Interface>> {
    getifaddrs_windows::get_if_addrs()
}

#[cfg(not(all(
    target_vendor = "apple",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
)))]
#[cfg_attr(docsrs, doc(cfg(not(target_vendor = "apple"))))]
mod if_change_notifier {
    use super::Interface;
    use std::collections::HashSet;
    use std::io;
    use std::time::{Duration, Instant};

    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub enum IfChangeType {
        Added(Interface),
        Removed(Interface),
    }

    #[cfg(windows)]
    type InternalIfChangeNotifier = crate::windows::WindowsIfChangeNotifier;
    #[cfg(not(windows))]
    type InternalIfChangeNotifier = crate::posix_not_apple::PosixIfChangeNotifier;

    /// (Not available on iOS/macOS) A utility to monitor for interface changes
    /// and report them, so you can handle events such as WiFi
    /// disconnection/flight mode/route changes
    pub struct IfChangeNotifier {
        inner: InternalIfChangeNotifier,
        last_ifs: HashSet<Interface>,
    }

    impl IfChangeNotifier {
        /// Create a new interface change notifier. Returns an OS specific error
        /// if the network notifier could not be set up.
        pub fn new() -> io::Result<Self> {
            Ok(Self {
                inner: InternalIfChangeNotifier::new()?,
                last_ifs: HashSet::from_iter(super::get_if_addrs()?),
            })
        }

        /// (Not available on iOS/macOS) Block until the OS reports that the
        /// network interface list has changed, or until an optional timeout.
        ///
        /// For example, if an ethernet connector is plugged/unplugged, or a
        /// WiFi network is connected to.
        ///
        /// The changed interfaces are returned. If an interface has both IPv4
        /// and IPv6 addresses, you can expect both of them to be returned from
        /// a single call to `wait`.
        ///
        /// Returns an [`io::ErrorKind::WouldBlock`] error on timeout, or
        /// another error if the network notifier could not be read from.
        pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<Vec<IfChangeType>> {
            let start = Instant::now();
            loop {
                self.inner
                    .wait(timeout.map(|t| t.saturating_sub(start.elapsed())))?;

                // something has changed - now we find out what (or whether it was spurious)
                let new_ifs = HashSet::from_iter(super::get_if_addrs()?);
                let mut changes: Vec<IfChangeType> = new_ifs
                    .difference(&self.last_ifs)
                    .cloned()
                    .map(IfChangeType::Added)
                    .collect();
                changes.extend(
                    self.last_ifs
                        .difference(&new_ifs)
                        .cloned()
                        .map(IfChangeType::Removed),
                );
                self.last_ifs = new_ifs;

                if !changes.is_empty() {
                    return Ok(changes);
                }
            }
        }
    }
}

#[cfg(not(all(
    target_vendor = "apple",
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
)))]
#[cfg_attr(docsrs, doc(cfg(not(target_vendor = "apple"))))]
pub use if_change_notifier::{IfChangeNotifier, IfChangeType};

#[cfg(test)]
mod tests {
    use super::{get_if_addrs, Interface};
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::process::{Command, Stdio};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    fn list_system_interfaces(cmd: &str, arg: &str) -> String {
        let start_cmd = if arg.is_empty() {
            Command::new(cmd).stdout(Stdio::piped()).spawn()
        } else {
            Command::new(cmd).arg(arg).stdout(Stdio::piped()).spawn()
        };
        let mut process = match start_cmd {
            Err(why) => {
                println!("couldn't start cmd {} : {}", cmd, why);
                return String::new();
            }
            Ok(process) => process,
        };
        thread::sleep(Duration::from_millis(1000));
        let _ = process.kill();
        let result: Vec<u8> = process
            .stdout
            .unwrap()
            .bytes()
            .map(|x| x.unwrap())
            .collect();
        String::from_utf8(result).unwrap()
    }

    #[cfg(windows)]
    fn list_system_addrs() -> Vec<IpAddr> {
        use std::net::Ipv6Addr;
        list_system_interfaces("ipconfig", "")
            .lines()
            .filter_map(|line| {
                println!("{}", line);
                if line.contains("Address") && !line.contains("Link-local") {
                    let addr_s: Vec<&str> = line.split(" : ").collect();
                    if line.contains("IPv6") {
                        return Some(IpAddr::V6(Ipv6Addr::from_str(addr_s[1]).unwrap()));
                    } else if line.contains("IPv4") {
                        return Some(IpAddr::V4(Ipv4Addr::from_str(addr_s[1]).unwrap()));
                    }
                }
                None
            })
            .collect()
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "nacl"))]
    fn list_system_addrs() -> Vec<IpAddr> {
        list_system_interfaces("ip", "addr")
            .lines()
            .filter_map(|line| {
                println!("{}", line);
                if line.contains("inet ") {
                    let addr_s: Vec<&str> = line.split_whitespace().collect();
                    let addr: Vec<&str> = addr_s[1].split('/').collect();
                    return Some(IpAddr::V4(Ipv4Addr::from_str(addr[0]).unwrap()));
                }
                None
            })
            .collect()
    }

    #[cfg(any(
        target_os = "freebsd",
        all(
            target_vendor = "apple",
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "watchos",
                target_os = "visionos"
            )
        )
    ))]
    fn list_system_addrs() -> Vec<IpAddr> {
        list_system_interfaces("ifconfig", "")
            .lines()
            .filter_map(|line| {
                println!("{}", line);
                if line.contains("inet ") {
                    let addr_s: Vec<&str> = line.split_whitespace().collect();
                    return Some(IpAddr::V4(Ipv4Addr::from_str(addr_s[1]).unwrap()));
                }
                None
            })
            .collect()
    }

    #[test]
    fn test_get_if_addrs() {
        let ifaces = get_if_addrs().unwrap();
        println!("Local interfaces:");
        println!("{:#?}", ifaces);
        // at least one loop back address
        assert!(
            1 <= ifaces
                .iter()
                .filter(|interface| interface.is_loopback())
                .count()
        );
        // if index is set, it is non-zero
        for interface in &ifaces {
            if let Some(idx) = interface.index {
                assert!(idx > 0);
            }
        }

        // one address of IpV4(127.0.0.1)
        let is_loopback =
            |interface: &&Interface| interface.addr.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(1, ifaces.iter().filter(is_loopback).count());

        // each system address shall be listed
        let system_addrs = list_system_addrs();
        assert!(!system_addrs.is_empty());
        for addr in system_addrs {
            let mut listed = false;
            println!("\n checking whether {:?} has been properly listed \n", addr);
            for interface in &ifaces {
                if interface.addr.ip() == addr {
                    listed = true;
                }

                assert!(interface.index.is_some());
            }
            assert!(listed);
        }
    }

    #[cfg(not(all(
        target_vendor = "apple",
        any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )
    )))]
    #[test]
    fn test_if_notifier() {
        // Check that the interface notifier can start up and time out. No easy
        // way to programmatically add/remove interfaces, so set a timeout of 0.
        // Will cover a potential case of inadequate setup leading to an
        // immediate change notification.
        //
        // There is a small race condition from creation -> check that an
        // interface change *actually* occurs, so this test may spuriously fail
        // extremely rarely.

        let notifier = crate::IfChangeNotifier::new();
        assert!(notifier.is_ok());
        let mut notifier = notifier.unwrap();

        assert!(notifier.wait(Some(Duration::ZERO)).is_err());
    }
}
