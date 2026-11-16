//! Implementation of `getifaddrs` / `freeifaddrs` on top of netlink (`NETLINK_ROUTE`).
//!
//! Used on Android versions whose libc doesn't provide them (API level < 24). Modeled after the
//! bionic implementation: links are dumped first (`RTM_GETLINK`) to obtain the interface names and
//! flags, then addresses (`RTM_GETADDR`). If the links can't be dumped (apps are not allowed to on
//! newer Android versions), the names and flags are resolved using `if_indextoname` and
//! `SIOCGIFFLAGS` instead. Unlike bionic, only entries with an IP address are returned (no
//! `AF_PACKET` ones).

use libc::{
    c_char, c_short, c_void, ifaddrs, sa_family_t, sockaddr_in, sockaddr_in6, sockaddr_storage,
    AF_INET, AF_INET6, AF_NETLINK, NETLINK_ROUTE, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW,
};
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
};

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x100 | 0x200; // NLM_F_ROOT | NLM_F_MATCH

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;

const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;

const IFLA_IFNAME: u16 = 3;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;

const IF_NAMESIZE: usize = 16;
const IFF_BROADCAST: u32 = 0x2;
const SIOCGIFFLAGS: u32 = 0x8913;

const RECV_BUFFER_LEN: usize = 64 * 1024;

/// Node of the `ifaddrs` linked list together with the storage its pointers point into.
#[repr(C)]
struct Node {
    // Must be the first field so that `*mut Node` can be cast to `*mut ifaddrs` and back.
    ifa: ifaddrs,
    name: CString,
    addr: sockaddr_storage,
    netmask: sockaddr_storage,
    ifu: sockaddr_storage,
}

struct Link {
    name: CString,
    flags: u32,
}

/// `struct ifreq` with only the `ifr_flags` member of the union. Padded to the size of the largest
/// member (`struct ifmap`) because the kernel copies the whole struct.
#[repr(C)]
struct IfReqFlags {
    name: [c_char; IF_NAMESIZE],
    flags: c_short,
    _pad: [u8; 22],
}

/// Returns the head of a linked list which must be freed with [`freeifaddrs`].
pub fn getifaddrs() -> io::Result<*mut ifaddrs> {
    getifaddrs_with(true)
}

fn getifaddrs_with(dump_links: bool) -> io::Result<*mut ifaddrs> {
    let socket = Socket::new()?;
    let mut links = HashMap::new();
    let mut nodes = Vec::new();

    if dump_links {
        // Failure is not fatal: the names and flags of any links we don't know about are resolved
        // in `parse_addr`. Any leftover responses to this request are skipped by `dump` thanks to
        // the sequence number.
        let _ = socket.dump(RTM_GETLINK, &[0; IFINFOMSG_LEN], |msg_type, payload| {
            if msg_type == RTM_NEWLINK {
                if let Some((index, link)) = parse_link(payload) {
                    links.insert(index, link);
                }
            }
        });
    }

    socket.dump(RTM_GETADDR, &[0; IFADDRMSG_LEN], |msg_type, payload| {
        if msg_type == RTM_NEWADDR {
            if let Some(node) = parse_addr(payload, &links) {
                nodes.push(node);
            }
        }
    })?;

    let mut head: *mut ifaddrs = ptr::null_mut();

    for mut node in nodes.into_iter().rev() {
        node.ifa.ifa_next = head;
        head = Box::into_raw(node).cast();
    }

    Ok(head)
}

/// Frees the list returned from [`getifaddrs`].
#[allow(unsafe_code)]
pub unsafe fn freeifaddrs(mut ifa: *mut ifaddrs) {
    while !ifa.is_null() {
        let node = Box::from_raw(ifa.cast::<Node>());
        ifa = node.ifa.ifa_next;
    }
}

fn parse_link(payload: &[u8]) -> Option<(u32, Link)> {
    if payload.len() < IFINFOMSG_LEN {
        return None;
    }

    let index = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
    let flags = u32::from_ne_bytes(payload[8..12].try_into().unwrap());

    let name = attrs(&payload[IFINFOMSG_LEN..])
        .find(|(attr_type, _)| *attr_type == IFLA_IFNAME)
        .and_then(|(_, data)| parse_name(data))?;

    Some((index, Link { name, flags }))
}

fn parse_name(data: &[u8]) -> Option<CString> {
    let name = data.split(|b| *b == 0).next().unwrap_or(data);

    if name.is_empty() {
        None
    } else {
        CString::new(name).ok()
    }
}

fn parse_addr(payload: &[u8], links: &HashMap<u32, Link>) -> Option<Box<Node>> {
    if payload.len() < IFADDRMSG_LEN {
        return None;
    }

    let family = i32::from(payload[0]);
    let prefixlen = payload[1];
    let index = u32::from_ne_bytes(payload[4..8].try_into().unwrap());

    let mut address = None;
    let mut local = None;
    let mut broadcast = None;
    let mut label = None;

    for (attr_type, data) in attrs(&payload[IFADDRMSG_LEN..]) {
        match attr_type {
            IFA_ADDRESS => address = parse_ip(family, data),
            IFA_LOCAL => local = parse_ip(family, data),
            // Only IPv4 has broadcast addresses.
            IFA_BROADCAST if family == AF_INET => broadcast = parse_ip(family, data),
            IFA_LABEL => label = parse_name(data),
            _ => (),
        }
    }

    // If `IFA_LOCAL` is present, it's the local address and `IFA_ADDRESS` is the destination
    // address (same as local unless point-to-point). Otherwise `IFA_ADDRESS` is the local address.
    // This matches what both glibc and bionic do.
    let (addr, dst) = match (local, address) {
        (Some(local), address) => (local, address),
        (None, Some(address)) => (address, None),
        (None, None) => return None,
    };

    let netmask = match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(prefix_to_mask(prefixlen, 32) as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(prefix_to_mask(prefixlen, 128))),
    };

    // The label (IPv4 only) distinguishes aliases (e.g. "eth0:1") so it takes precedence over the
    // link name. If we know neither, the address is skipped (like bionic does).
    let link = links.get(&index);
    let name = label
        .or_else(|| link.map(|link| link.name.clone()))
        .or_else(|| index_to_name(index))?;

    let flags = match link {
        Some(link) => link.flags,
        None => name_to_flags(&name).unwrap_or(if broadcast.is_some() {
            IFF_BROADCAST
        } else {
            0
        }),
    };

    // SAFETY: all-zero bit pattern is valid for these types.
    #[allow(unsafe_code)]
    let mut node = Box::new(Node {
        ifa: unsafe { mem::zeroed() },
        name,
        addr: unsafe { mem::zeroed() },
        netmask: unsafe { mem::zeroed() },
        ifu: unsafe { mem::zeroed() },
    });

    write_sockaddr(&mut node.addr, addr, index);
    write_sockaddr(&mut node.netmask, netmask, 0);

    node.ifa.ifa_name = node.name.as_ptr().cast_mut();
    node.ifa.ifa_flags = flags;
    node.ifa.ifa_addr = ptr::addr_of_mut!(node.addr).cast();
    node.ifa.ifa_netmask = ptr::addr_of_mut!(node.netmask).cast();

    // `ifa_ifu` is a union of `ifa_broadaddr` and `ifa_dstaddr`. If both are present, the
    // broadcast address wins (the kernel sends it last and bionic keeps the last one).
    if let Some(ifu) = broadcast.or(dst) {
        write_sockaddr(&mut node.ifu, ifu, index);
        node.ifa.ifa_ifu = ptr::addr_of_mut!(node.ifu).cast();
    }

    Some(node)
}

#[allow(unsafe_code)]
fn index_to_name(index: u32) -> Option<CString> {
    let mut buf: [c_char; IF_NAMESIZE] = [0; IF_NAMESIZE];

    if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
        return None;
    }

    // SAFETY: on success, `if_indextoname` writes a nul-terminated string into `buf`.
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) };

    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

#[allow(unsafe_code)]
fn name_to_flags(name: &CStr) -> Option<u32> {
    let fd = unsafe { libc::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req = IfReqFlags {
        name: [0; IF_NAMESIZE],
        flags: 0,
        _pad: [0; 22],
    };

    // Leave room for the nul terminator.
    for (dst, src) in req
        .name
        .iter_mut()
        .zip(name.to_bytes().iter().take(IF_NAMESIZE - 1))
    {
        *dst = *src as c_char;
    }

    // The type of the request argument differs between platforms (`c_int` on Android, `c_ulong` on
    // glibc).
    if unsafe { libc::ioctl(fd.as_raw_fd(), SIOCGIFFLAGS as _, &mut req) } < 0 {
        return None;
    }

    // `ifr_flags` is a `short` but the flags in `ifaddrs` are `unsigned int`, so zero-extend.
    Some(u32::from(req.flags as u16))
}

fn parse_ip(family: i32, data: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
        AF_INET6 => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
        _ => None,
    }
}

fn prefix_to_mask(prefixlen: u8, bits: u32) -> u128 {
    let prefixlen = u32::from(prefixlen).min(bits);

    if prefixlen == 0 {
        0
    } else {
        (u128::MAX << (128 - prefixlen)) >> (128 - bits)
    }
}

/// Link-local unicast (fe80::/10) or link-local multicast (ffx2::/16) IPv6 address. These get the
/// interface index as their scope id.
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    let segment = addr.segments()[0];
    segment & 0xffc0 == 0xfe80 || segment & 0xff0f == 0xff02
}

/// Writes `addr` into `storage`. `index` is the interface index, used as the scope id of IPv6
/// link-local addresses (pass 0 if not applicable).
#[allow(unsafe_code)]
fn write_sockaddr(storage: &mut sockaddr_storage, addr: IpAddr, index: u32) {
    match addr {
        IpAddr::V4(addr) => {
            // SAFETY: `sockaddr_storage` is large enough and suitably aligned for any sockaddr.
            let sa = unsafe { &mut *(storage as *mut sockaddr_storage).cast::<sockaddr_in>() };
            sa.sin_family = AF_INET as sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
        }
        IpAddr::V6(addr) => {
            // SAFETY: `sockaddr_storage` is large enough and suitably aligned for any sockaddr.
            let sa = unsafe { &mut *(storage as *mut sockaddr_storage).cast::<sockaddr_in6>() };
            sa.sin6_family = AF_INET6 as sa_family_t;
            sa.sin6_addr.s6_addr = addr.octets();

            if is_ipv6_link_local(&addr) {
                sa.sin6_scope_id = index;
            }
        }
    }
}

/// Iterates over the route attributes (`struct rtattr`) in the buffer, yielding `(type, data)`.
fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }

        let len = usize::from(u16::from_ne_bytes([buf[0], buf[1]]));
        let attr_type = u16::from_ne_bytes([buf[2], buf[3]]);

        if len < 4 || len > buf.len() {
            return None;
        }

        let data = &buf[4..len];
        buf = &buf[align(len).min(buf.len())..];

        Some((attr_type, data))
    })
}

const fn align(len: usize) -> usize {
    (len + 3) & !3
}

struct Socket(OwnedFd);

impl Socket {
    #[allow(unsafe_code)]
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };

        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
    }

    /// Sends a dump request of the given type and invokes `f` with the type and payload of every
    /// message in the response.
    fn dump(&self, msg_type: u16, body: &[u8], mut f: impl FnMut(u16, &[u8])) -> io::Result<()> {
        // Use the request type as the sequence number to tell responses to different requests
        // apart.
        let seq = u32::from(msg_type);

        let mut request = Vec::with_capacity(NLMSG_HDR_LEN + body.len());
        request.extend_from_slice(&((NLMSG_HDR_LEN + body.len()) as u32).to_ne_bytes());
        request.extend_from_slice(&msg_type.to_ne_bytes());
        request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&seq.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes()); // pid
        request.extend_from_slice(body);

        self.send(&request)?;

        let mut buf = vec![0; RECV_BUFFER_LEN];

        loop {
            let len = self.recv(&mut buf)?;

            if len == 0 {
                // Shouldn't happen, but avoid looping forever if it does.
                return Err(io::ErrorKind::UnexpectedEof.into());
            }

            let mut msgs = &buf[..len];

            while msgs.len() >= NLMSG_HDR_LEN {
                let msg_len = u32::from_ne_bytes(msgs[0..4].try_into().unwrap()) as usize;
                let msg_type = u16::from_ne_bytes(msgs[4..6].try_into().unwrap());
                let msg_seq = u32::from_ne_bytes(msgs[8..12].try_into().unwrap());

                if msg_len < NLMSG_HDR_LEN || msg_len > msgs.len() {
                    return Err(io::Error::from_raw_os_error(libc::EBADMSG));
                }

                let payload = &msgs[NLMSG_HDR_LEN..msg_len];
                msgs = &msgs[align(msg_len).min(msgs.len())..];

                if msg_seq != seq {
                    continue;
                }

                match msg_type {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        let error = payload
                            .get(0..4)
                            .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADMSG))?;

                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                    }
                    _ => f(msg_type, payload),
                }
            }
        }
    }

    #[allow(unsafe_code)]
    fn send(&self, buf: &[u8]) -> io::Result<()> {
        loop {
            let res = unsafe {
                libc::send(
                    self.0.as_raw_fd(),
                    buf.as_ptr() as *const c_void,
                    buf.len(),
                    0,
                )
            };

            if res >= 0 {
                return Ok(());
            }

            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[allow(unsafe_code)]
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let res = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                    0,
                )
            };

            if res >= 0 {
                return Ok(res as usize);
            }

            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sockaddr;
    use std::ffi::CStr;

    type Entry = (String, u32, Option<IpAddr>, Option<IpAddr>, Option<IpAddr>);

    #[allow(unsafe_code)]
    unsafe fn collect(mut ifa: *mut ifaddrs, flags_mask: u32) -> Vec<Entry> {
        let mut entries = Vec::new();

        while !ifa.is_null() {
            let i = &*ifa;
            let addr = sockaddr::to_ipaddr(i.ifa_addr as *const libc::sockaddr);

            if addr.is_some() {
                entries.push((
                    CStr::from_ptr(i.ifa_name).to_string_lossy().into_owned(),
                    i.ifa_flags & flags_mask,
                    addr,
                    sockaddr::to_ipaddr(i.ifa_netmask as *const libc::sockaddr),
                    sockaddr::to_ipaddr(i.ifa_ifu as *const libc::sockaddr),
                ));
            }

            ifa = i.ifa_next;
        }

        entries.sort();
        entries
    }

    // Compares the netlink implementation with the one from libc (where available).
    #[test]
    fn matches_libc() {
        check_matches_libc(getifaddrs(), u32::MAX);
    }

    // Same as `matches_libc` but without dumping the links, to exercise the fallback for when
    // that's not allowed. The flags then come from `SIOCGIFFLAGS` which only returns the lower 16
    // bits (same as in bionic).
    #[test]
    fn matches_libc_without_links() {
        check_matches_libc(getifaddrs_with(false), 0xffff);
    }

    #[allow(unsafe_code)]
    fn check_matches_libc(actual: io::Result<*mut ifaddrs>, flags_mask: u32) {
        let actual = actual.unwrap();
        let actual_entries = unsafe { collect(actual, flags_mask) };
        unsafe { freeifaddrs(actual) };

        assert!(!actual_entries.is_empty());

        #[cfg(target_os = "android")]
        let (libc_getifaddrs, libc_freeifaddrs) = match crate::android::libc_fns() {
            Some(fns) => fns,
            None => return,
        };
        #[cfg(not(target_os = "android"))]
        let (libc_getifaddrs, libc_freeifaddrs) = (libc::getifaddrs, libc::freeifaddrs);

        let mut expected = ptr::null_mut();
        assert_eq!(unsafe { libc_getifaddrs(&mut expected) }, 0);
        let expected_entries = unsafe { collect(expected, flags_mask) };
        unsafe { libc_freeifaddrs(expected) };

        assert_eq!(actual_entries, expected_entries);
    }

    #[test]
    fn prefix_to_mask_works() {
        assert_eq!(prefix_to_mask(0, 32), 0);
        assert_eq!(prefix_to_mask(24, 32), 0xffff_ff00);
        assert_eq!(prefix_to_mask(32, 32), 0xffff_ffff);
        assert_eq!(prefix_to_mask(64, 128), u128::MAX << 64);
        assert_eq!(prefix_to_mask(128, 128), u128::MAX);
    }
}
