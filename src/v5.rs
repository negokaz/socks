// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

use address::Addr;
use address::DomainAddr;
use address::ToAddr;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use futures::Future;
use futures::done;
use futures::failed;
use protocol::*;
use std::convert::TryInto;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::str;
use tokio_core::io::read_exact;
use tokio_core::io::write_all;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;

/// Crates a new connection through a SOCKS5 proxy.
pub fn connect<D>(proxy: &SocketAddr, dest_addr: D, handle: &Handle) -> IoFuture<(Addr, TcpStream)>
    where D: ToAddr
{
    let dest_addr = match dest_addr.to_addr() {
        Err(e) => return Box::new(failed(e)),
        Ok(a) => a
    };
    Box::new(TcpStream::connect(&proxy, handle).and_then(|stream| {
        connect_stream(stream, dest_addr)
    }))
}

/// Crates a new connection through SOCKS5 proxy using an existing stream.
#[doc(hidden)]
pub fn connect_stream<S, D>(stream: S, dest_addr: D) -> IoFuture<(Addr, S)>
    where S: Read + Write + 'static,
          D: ToAddr
{
    let dest_addr = match dest_addr.to_addr() {
        Err(e) => return Box::new(failed(e)),
        Ok(a) => a,
    };

    // Send socks version and supported authentication methods.
    Box::new(write_all(stream, vec![VERSION, 1, AUTH_NONE]).and_then(|(stream, mut buff)| {
        // Receive server version and selected authentication method.
        buff.resize(2, 0);
        read_exact(stream, buff)
    }).and_then(move |(stream, mut buff)| {
        // Parse and validate authentication method.
        done(if buff[0] != VERSION {
            Err(invalid_data("proxy: Invalid version in response (not a SOCKS5 proxy?)"))
        } else if buff[1] == AUTH_NO_ACCEPTABLE {
            Err(other("proxy: No acceptable authentication methods"))
        } else if buff[1] != AUTH_NONE {
            Err(invalid_data("proxy: Server selected an invalid authentication method"))
        } else {
            // Prepare connect request.
            buff.clear();
            buff.extend(&[VERSION, CMD_CONNECT, RSV]);
            write_address(&mut buff, &dest_addr).and(Ok((stream, buff)))
        }).and_then(|(stream, buff)| {
            // Send connect request
            write_all(stream, buff)
        })
    }).and_then(|(stream, mut buff)| {
        // Read reply up to variable length address.
        buff.resize(4, 0);
        read_exact(stream, buff)
    }).and_then(|(stream, buff)| {
        // Parse and validate reply to connect request.
        done(if buff[0] != VERSION {
            Err(invalid_data("proxy: received invalid version in response"))
        } else if buff[2] != RSV {
            Err(invalid_data("proxy: received invalid non-zero reserved field"))
        } else { match buff[1] {
            0 => Ok((stream, buff)),
            1 => Err(other("proxy: General SOCKS server failure")),
            2 => Err(other("proxy: Connection not allowed by ruleset")),
            3 => Err(other("proxy: Network unreachable")),
            4 => Err(other("proxy: Host unreachable")),
            5 => Err(other("proxy: Connection refused")),
            6 => Err(other("proxy: TTL expired")),
            7 => Err(other("proxy: Command not supported")),
            8 => Err(other("proxy: Address type not supported")),
            code => Err(other(format!("proxy: Error {}", code))),
        }}).and_then(|(stream, buff)| {
            // Read address from response.
            match buff[3] {
                ATYP_IPV4 => read_ipv4_address(stream, buff),
                ATYP_IPV6 => read_ipv6_address(stream, buff),
                ATYP_DOMAIN_NAME => read_domain_address(stream, buff),
                _ => Box::new(failed(other(format!("proxy: Unsupported address type {}", buff[3])))),
            }
        })
    }))
}

fn write_address(buffer: &mut Vec<u8>, address: &Addr) -> Result<()> {
    match *address {
        Addr::V4(ref sa) => {
            try!(buffer.write(&[ATYP_IPV4]));
            try!(buffer.write(&sa.ip().octets()));
            write_port(buffer, sa.port())
        },
        Addr::V6(ref sa) => {
            try!(buffer.write(&[ATYP_IPV6]));
            try!(buffer.write(&sa.ip().octets()));
            write_port(buffer, sa.port())
        }
        Addr::Domain(ref da) => {
            try!(buffer.write(&[ATYP_DOMAIN_NAME]));
            try!(write_domain(buffer, da.domain()));
            write_port(buffer, da.port())
        }
    }
}

fn write_domain(buffer: &mut Vec<u8>, domain: &str) -> Result<()> {
    let length = try!(domain.len().try_into() .map_err(|_| {
        invalid_input(format!("proxy: invalid domain name: {}", domain))
    }));
    try!(buffer.write(&[length]));
    try!(buffer.write(domain.as_bytes()));
    Ok(())
}

fn read_ipv4_address<S: Read + 'static>(stream: S, mut buff: Vec<u8>) -> IoFuture<(Addr, S)> {
    // Read IPv4 address and port.
    buff.resize(6, 0);
    Box::new(read_exact(stream, buff).map(|(stream, buff)| {
        // Parse IPv4 address and port.
        let ip = Ipv4Addr::new(buff[0], buff[1], buff[2], buff[3]);
        let port = BigEndian::read_u16(&buff[4..6]);
        (Addr::V4(SocketAddrV4::new(ip, port)), stream)
    }))
}

fn read_ipv6_address<S: Read + 'static>(stream: S, mut buff: Vec<u8>) -> IoFuture<(Addr, S)> {
    // Read IPv6 address and port.
    buff.resize(18, 0);
    Box::new(read_exact(stream, buff).map(|(stream, buff)| {
        // Parse IPv6 address and port.
        let ip = Ipv6Addr::new(
            BigEndian::read_u16(&buff[0..2]),
            BigEndian::read_u16(&buff[2..4]),
            BigEndian::read_u16(&buff[4..6]),
            BigEndian::read_u16(&buff[6..8]),
            BigEndian::read_u16(&buff[8..10]),
            BigEndian::read_u16(&buff[10..12]),
            BigEndian::read_u16(&buff[12..14]),
            BigEndian::read_u16(&buff[14..16]));
        let port = BigEndian::read_u16(&buff[16..18]);
        (Addr::V6(SocketAddrV6::new(ip, port, 0, 0)), stream)
    }))
}

fn read_domain_address<S: Read + 'static>(stream: S, mut buff: Vec<u8>) -> IoFuture<(Addr, S)> {
    // Read domain name length.
    buff.resize(1, 0);
    Box::new(read_exact(stream, buff).and_then(|(stream, mut buff)| {
        // Read domain name and port.
        let domain_length = usize::from(buff[0]) + 2;
        buff.resize(domain_length, 0);
        read_exact(stream, buff)
    }).and_then(|(stream, buff)| {
        // Parse domain name and port
        let domain_length = buff.len() - 2;
        str::from_utf8(&buff[0..domain_length]).map_err(|_| {
            invalid_data("proxy: received invalid domain name")
        }).map(|domain| {
            let port = BigEndian::read_u16(&buff[domain_length..]);
            (Addr::Domain(DomainAddr::new(domain, port)), stream)
        })
    }))
}

// Constants used in SOCKS version 5.
pub const VERSION: u8 = 5;
pub const AUTH_NONE: u8 = 0;
pub const AUTH_NO_ACCEPTABLE: u8 = 255;
pub const CMD_CONNECT: u8 = 1;
pub const RSV: u8 = 0;
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_IPV6: u8 = 4;
pub const ATYP_DOMAIN_NAME: u8 = 3;

#[cfg(test)]
mod tests {
    use address::*;
    use protocol::test::*;
    use std::str::FromStr;
    use tokio_core::reactor::Core;
    use v5::*;

    const REP_SUCCEEDED: u8 = 0;

    #[test]
    fn connect_ipv4() {
        let stream = Stream::new(&[
            VERSION, AUTH_NONE,
            VERSION, REP_SUCCEEDED, RSV, ATYP_IPV4,
            192, 168, 1, 2,
            8, 1,
        ]);
        let mut reactor = Core::new().unwrap();
        let (addr, stream) = reactor.run(connect_stream(stream, "1.2.3.4:5")).unwrap();

        assert_eq!(Addr::from_str("192.168.1.2:2049").unwrap(), addr);
        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RSV, ATYP_IPV4,
                    1, 2, 3, 4, 0, 5],
                   stream.write_buffer());
        assert!(stream.read_all());
    }

    #[test]
    fn connect_ipv6() {
        let stream = Stream::new(&[
            VERSION, AUTH_NONE,
            VERSION, REP_SUCCEEDED, RSV, ATYP_IPV6,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            1, 2, 3, 4,
            8, 0,
        ]);

        let mut reactor = Core::new().unwrap();
        let (addr, stream) = reactor.run(connect_stream(stream, "[::ffff:192.168.0.1]:80")).unwrap();

        assert_eq!(Addr::from_str("[::1.2.3.4]:2048").unwrap(), addr);
        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RSV, ATYP_IPV6,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 255, 255,
                    192, 168, 0, 1,
                    0, 80],
                   stream.write_buffer());
        assert!(stream.read_all());
    }

    #[test]
    fn connect_domain_name() {
        let stream = Stream::new(&[
            VERSION, AUTH_NONE,
            VERSION, REP_SUCCEEDED, RSV, ATYP_DOMAIN_NAME,
            5, b'a', b'.', b'c', b'o', b'm',
            250, 0
        ]);

        let mut reactor = Core::new().unwrap();
        let (addr, stream) = reactor.run(connect_stream(stream, "z.com:80")).unwrap();

        assert_eq!(Addr::from_str("a.com:64000").unwrap(), addr);
        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RSV, ATYP_DOMAIN_NAME,
                    5, b'z', b'.', b'c', b'o', b'm',
                    0, 80],
                   stream.write_buffer());
        assert!(stream.read_all());
    }

    #[test]
    fn connect_auth_not_acceptable() {
        let stream = Stream::new(&[
            VERSION, AUTH_NO_ACCEPTABLE,
        ]);
        let future = connect_stream(stream, "a.com:80");
        let mut reactor = Core::new().unwrap();
        let error = reactor.run(future).err().unwrap();
        assert_eq!("proxy: No acceptable authentication methods", format!("{}", error));
    }
}
