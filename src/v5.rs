// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

//! Implementation of SOCKS5 protocol.

use address::Addr;
use address::DomainAddr;
use address::ToAddr;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use futures::Future;
use futures::done;
use futures::failed;
use futures::finished;
use protocol::*;
use self::consts::*;
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

/// Authentication method.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Auth {
    /// No authentication.
    None,
    /// Authenticate with provided username and password.
    UserPass(String, String),
}

/// Crates a new connection through a SOCKS5 proxy.
///
/// If destination address is provided as a domain name, then hostname is
/// resolved by proxy.
pub fn connect<D>(proxy: &SocketAddr, destination: D, auth: Auth, handle: &Handle) -> IoFuture<TcpStream>
    where D: ToAddr
{
    let connection = TcpStream::connect(&proxy, handle);
    Box::new(done(destination.to_addr()).and_then(|address| {
        connection.and_then(|stream| {
            connect_stream(stream, address, auth)
        })
    }))
}

/// Crates a new connection through SOCKS5 proxy using an existing stream.
#[doc(hidden)]
pub fn connect_stream<S>(stream: S, destination: Addr, auth: Auth) -> IoFuture<S>
    where S: Read + Write + 'static
{
    let auth_method = match auth {
        Auth::None => AUTH_NONE,
        Auth::UserPass(..) => AUTH_USER_PASS,
    };

    Box::new(
        // Send socks version and selected authentication method.
        write_all(stream, vec![VERSION, 1, auth_method]
    ).and_then(|(stream, mut buff)| {
        // Receive server version and selected authentication method.
        buff.resize(2, 0);
        read_exact(stream, buff)
    }).and_then(move |(stream, buff)| {
        // Parse and validate authentication method.
        if buff[0] != VERSION {
            return Err(invalid_data("proxy: Invalid version in response (not a SOCKS5 proxy?)"))
        }
        if buff[1] == AUTH_NO_ACCEPTABLE {
            return Err(other("proxy: No acceptable authentication methods"))
        }
        if buff[1] != auth_method {
            return Err(invalid_data("proxy: Server selected an invalid authentication method"))
        } 
        Ok((stream, buff))
    }).and_then(|(stream, buff)| {
        authenticate(stream, buff, auth)
    }).and_then(move |(stream, mut buff)| {
        // Prepare connect request.
        buff.clear();
        buff.extend(&[VERSION, CMD_CONNECT, RESERVED]);
        write_address(&mut buff, &destination).and(Ok((stream, buff)))
    }).and_then(|(stream, buff)| {
        // Send connect request
        write_all(stream, buff)
    }).and_then(|(stream, mut buff)| {
        // Read reply up to variable length address.
        buff.resize(4, 0);
        read_exact(stream, buff)
    }).and_then(|(stream, buff)| {
        // Parse and validate reply to connect request.
        if buff[0] != VERSION {
            return Err(invalid_data("proxy: received invalid version in response"));
        }
        if buff[2] != RESERVED {
            return Err(invalid_data("proxy: received invalid non-zero reserved field"))
        }
        match buff[1] {
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
        }
    }).and_then(|(stream, buff)| {
        // Read address from response.
        match buff[3] {
            ATYP_IPV4 => read_ipv4_address(stream, buff),
            ATYP_IPV6 => read_ipv6_address(stream, buff),
            ATYP_DOMAIN_NAME => read_domain_address(stream, buff),
            _ => Box::new(failed(other(format!("proxy: Unsupported address type {}", buff[3])))),
        }
    }).map(|(_, stream)| {
        stream
    }))
}

fn authenticate<S>(stream: S, mut buffer: Vec<u8>, auth: Auth) -> IoFuture<(S, Vec<u8>)>
    where S: Read + Write + 'static
{
    match auth {
        Auth::None => Box::new(finished((stream, buffer))),
        Auth::UserPass(ref user, ref pass) => {
            Box::new(done((|| {
                let user_len = try!(user.len().try_into().map_err(|_| invalid_input("proxy: Username length exceeds 255 bytes")));
                let pass_len = try!(pass.len().try_into().map_err(|_| invalid_input("proxy: Password length exceeds 255 bytes")));
                buffer.clear();
                try!(buffer.write(&[AUTH_USER_PASS_VERSION, user_len]));
                try!(buffer.write(user.as_bytes()));
                try!(buffer.write(&[pass_len]));
                try!(buffer.write(pass.as_bytes()));
                Ok(buffer)
            })()).and_then(|buffer| {
                write_all(stream, buffer)
            }).and_then(|(stream, mut buffer)| {
                buffer.resize(2, 0);
                read_exact(stream, buffer)
            }).and_then(|(stream, buffer)| {
                if buffer[0] != AUTH_USER_PASS_VERSION {
                    return Err(invalid_data("proxy: Invalid authentication version in response"))
                }
                if buffer[1] != AUTH_SUCCEEDED {
                    return Err(other("proxy: Authentication failure"))
                }
                Ok((stream, buffer))
            }))
        }
    }
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

/// Constants used in SOCKS version 5.
mod consts {
    pub const VERSION: u8 = 5;
    pub const AUTH_NONE: u8 = 0;
    pub const AUTH_USER_PASS: u8 = 2;
    pub const AUTH_USER_PASS_VERSION: u8 = 1;
    pub const AUTH_SUCCEEDED: u8 = 0;
    pub const AUTH_NO_ACCEPTABLE: u8 = 255;
    pub const CMD_CONNECT: u8 = 1;
    pub const RESERVED: u8 = 0;
    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN_NAME: u8 = 3;
}

#[cfg(test)]
mod tests {
    use address::*;
    use protocol::test::*;
    use tokio_core::reactor::Core;
    use v5::*;
    use v5::consts::*;

    const REP_SUCCEEDED: u8 = 0;

    #[test]
    fn connect_ipv4() {
        let stream = Stream::new(&[
            VERSION, AUTH_NONE,
            VERSION, REP_SUCCEEDED, RESERVED, ATYP_IPV4,
            192, 168, 1, 2,
            8, 1,
        ]);
        let mut reactor = Core::new().unwrap();
        let address = "1.2.3.4:5".to_addr().unwrap();
        let stream = reactor.run(connect_stream(stream, address, Auth::None)).unwrap();

        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RESERVED, ATYP_IPV4,
                    1, 2, 3, 4, 0, 5],
                   stream.write_buffer());
        assert!(stream.read_all());
    }

    #[test]
    fn connect_ipv6() {
        let stream = Stream::new(&[
            VERSION, AUTH_NONE,
            VERSION, REP_SUCCEEDED, RESERVED, ATYP_IPV6,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            1, 2, 3, 4,
            8, 0,
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "[::ffff:192.168.0.1]:80".to_addr().unwrap();
        let stream = reactor.run(connect_stream(stream, address, Auth::None)).unwrap();

        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RESERVED, ATYP_IPV6,
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
            VERSION, REP_SUCCEEDED, RESERVED, ATYP_DOMAIN_NAME,
            5, b'a', b'.', b'c', b'o', b'm',
            250, 0
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "z.com:80".to_addr().unwrap();
        let stream = reactor.run(connect_stream(stream, address, Auth::None)).unwrap();

        assert_eq!([VERSION, 1, AUTH_NONE,
                    VERSION, CMD_CONNECT, RESERVED, ATYP_DOMAIN_NAME,
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

        let mut reactor = Core::new().unwrap();
        let address = "a.com:80".to_addr().unwrap();
        let error = reactor.run(connect_stream(stream, address, Auth::None)).err().unwrap();
        assert_eq!("proxy: No acceptable authentication methods", format!("{}", error));
    }

    #[test]
    fn connect_auth_user_pass() {
        let stream = Stream::new(&[
            VERSION, AUTH_USER_PASS,
            AUTH_USER_PASS_VERSION, AUTH_SUCCEEDED,
            VERSION, REP_SUCCEEDED, RESERVED, ATYP_IPV4, 1, 2, 3, 4, 0, 80
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "8.8.8.8:20".to_addr().unwrap();
        let auth = Auth::UserPass("root".to_owned(), "secret".to_owned());
        let stream = reactor.run(connect_stream(stream, address, auth)).unwrap();

        assert!(stream.read_all());
        assert_eq!([VERSION, 1, AUTH_USER_PASS,
                    AUTH_USER_PASS_VERSION, 
                    4, b'r', b'o', b'o', b't', 
                    6, b's', b'e', b'c', b'r', b'e', b't',
                    VERSION, CMD_CONNECT, RESERVED, ATYP_IPV4,
                    8, 8, 8, 8,
                    0, 20],
                   stream.write_buffer());
    }

    #[test]
    fn connect_auth_failed() {
        let stream = Stream::new(&[
            VERSION, AUTH_USER_PASS,
            AUTH_USER_PASS_VERSION, !AUTH_SUCCEEDED,
            VERSION, REP_SUCCEEDED, RESERVED, ATYP_IPV4, 1, 2, 3, 4, 0, 80
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "a.com:80".to_addr().unwrap();
        let auth = Auth::UserPass("root".to_owned(), "secret".to_owned());
        let error = reactor.run(connect_stream(stream, address, auth)).err().unwrap();

        assert_eq!("proxy: Authentication failure",
                   format!("{}", error));
    }
}
