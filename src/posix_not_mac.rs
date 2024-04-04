use std::io;
use std::mem;
use std::time::Duration;

use libc::{
    bind, c_int, c_void, close, recv, setsockopt, sockaddr_nl, socket, socklen_t, ssize_t, timeval,
    AF_NETLINK, NETLINK_ROUTE, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO,
};

#[repr(transparent)]
struct NetlinkSocket(c_int);

impl NetlinkSocket {
    fn new() -> io::Result<Self> {
        Ok(NetlinkSocket(check_io(unsafe {
            socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
        })?))
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { close(self.0) };
    }
}

fn check_io(res: c_int) -> io::Result<c_int> {
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res)
    }
}

fn check_recv(res: ssize_t) -> io::Result<ssize_t> {
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res)
    }
}

pub fn detect_interface_changes(timeout: Option<Duration>) -> io::Result<()> {
    let socket = NetlinkSocket::new()?;

    let mut sockaddr: sockaddr_nl = unsafe { mem::zeroed() };
    sockaddr.nl_family = AF_NETLINK as u16;
    sockaddr.nl_groups = 1; // RTNLGRP_LINK

    check_io(unsafe {
        bind(
            socket.0,
            &sockaddr as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as libc::socklen_t,
        )
    })?;

    // TODO: When MSRV moves beyond Rust 1.66, this can be cleaner as
    // let mut socket = UdpSocket::from_raw_fd(socket);
    // socket.set_read_timeout(timeout)?;
    // socket.recv(&mut buf)?;

    if let Some(timeout) = timeout {
        let t = timeval {
            tv_sec: timeout.as_secs().try_into().expect("timeout overflow"),
            tv_usec: timeout
                .subsec_micros()
                .try_into()
                .expect("timeout overflow"),
        };
        check_io(unsafe {
            setsockopt(
                socket.0,
                SOL_SOCKET,
                SO_RCVTIMEO,
                core::ptr::addr_of!(t) as *const _,
                mem::size_of::<timeval>() as socklen_t,
            )
        })?;
    }
    let mut buf = [0u8; 65536];
    check_recv(unsafe { recv(socket.0, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) })?;

    Ok(())
}
