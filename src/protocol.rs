use address::Addr;
use address::DomainAddr;
use address::ToAddr;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use futures::Future;
use futures::done;
use futures::failed;
use std::convert::TryInto;
use std::error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::io;
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

type IoFuture<T> = Box<Future<Item=T, Error=io::Error>>;

pub fn connect<D: ToAddr>(proxy: &SocketAddr, dest: D, handle: &Handle) -> IoFuture<(Addr, TcpStream)> {
    let dest = match dest.to_addr() {
        Err(e) => return Box::new(failed(e)),
        Ok(a) => a
    };
    Box::new(TcpStream::connect(&proxy, handle).and_then(|stream| {
        connect_stream(stream, dest)
    }))
}

pub fn connect_stream<S: Read + Write + 'static, D: ToAddr>(stream: S, dest: D) -> IoFuture<(Addr, S)> {
    let dest = match dest.to_addr() {
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
            Err(invalid_data("socks: Invalid version in response (not a socks 5 proxy?)"))
        } else if buff[1] == AUTH_NO_ACCEPTABLE {
            Err(other("socks: None of authentication methods is acceptable to server"))
        } else if buff[1] != AUTH_NONE {
            Err(invalid_data("socks: Server selected an invalid authentication method"))
        } else {
            // Prepare connect request.
            buff.clear();
            buff.extend(&[VERSION, CMD_CONNECT, RSV]);
            write_address(&mut buff, &dest).unwrap();
            Ok((stream, buff))
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
            Err(invalid_data("socks: received invalid version in response"))
        } else if buff[2] != RSV {
            Err(invalid_data("socks: received invalid non-zero reserved field"))
        } else { match buff[1] {
            0 => Ok((stream, buff)),
            1 => Err(other("socks-reply: General socks server failure")),
            2 => Err(other("socks-reply: Connection not allowed by ruleset")),
            3 => Err(other("socks-reply: Network unreachable")),
            4 => Err(other("socks-reply: Host unreachable")),
            5 => Err(other("socks-reply: Connection refused")),
            6 => Err(other("socks-reply: TTL expired")),
            7 => Err(other("socks-reply: Command not supported")),
            8 => Err(other("socks-reply: Address type not supported")),
            code => Err(other(format!("socks-reply: Error {}", code))),
        }}).and_then(|(stream, buff)| {
            // Read address from response.
            match buff[3] {
                ATYP_IPV4 => read_ipv4_address(stream, buff),
                ATYP_IPV6 => read_ipv6_address(stream, buff),
                ATYP_DOMAIN_NAME => read_domain_address(stream, buff),
                _ => Box::new(failed(other(format!("socks: Unsupported address type {}", buff[3])))),
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

fn write_port(buffer: &mut Vec<u8>, port: u16) -> Result<()> {
    try!(buffer.write(&[((port >> 8) & 0xff) as u8,
                        ((port >> 0) & 0xff) as u8]));
    Ok(())
}

fn write_domain(buffer: &mut Vec<u8>, domain: &str) -> Result<()> {
    let length = try!(domain.len().try_into() .map_err(|_| {
        other("domain names longer than 255 bytes are unsupported by SOCKSv5 protocol.")
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
    }).map(|(stream, buff)| {
        // Parse domain name and port
        let domain_length = buff.len() - 2;
        let domain = str::from_utf8(&buff[0..domain_length]).unwrap();
        let port = BigEndian::read_u16(&buff[domain_length..]);
        (Addr::Domain(DomainAddr::new(domain, port)), stream)
    }))
}

fn other<E>(error: E) -> io::Error
    where E: Into<Box<error::Error + Send + Sync>>
{
    io::Error::new(ErrorKind::Other, error)
}

fn invalid_data<E>(error: E) -> io::Error
    where E: Into<Box<error::Error + Send + Sync>>
{
    io::Error::new(ErrorKind::InvalidData, error)
}

// Constants used in SOCKS version 5 protocol.
const VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_NO_ACCEPTABLE: u8 = 255;
const CMD_CONNECT: u8 = 1;
const RSV: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 4;
const ATYP_DOMAIN_NAME: u8 = 3;

