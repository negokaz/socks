// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

//! Implementation of SOCKS4a protocol.

use address::Addr;
use address::ToAddr;
use common::*;
use futures::Future;
use futures::done;
use self::consts::*;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::SocketAddr;
use tokio_core::io::IoFuture;
use tokio_core::io::read_exact;
use tokio_core::io::write_all;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;

/// Crates a new connection through a SOCKS4a proxy.
///
/// If destination address is provided as a domain name, then hostname is
/// resolved by proxy.
pub fn connect<D>(proxy: &SocketAddr, destination: D, handle: &Handle) -> IoFuture<TcpStream>
    where D: ToAddr
{
    let connection = TcpStream::connect(&proxy, handle);
    Box::new(done(destination.to_addr()).and_then(|address| {
        connection.and_then(|stream| {
            connect_stream(stream, address)
        })
    }))
}

/// Crates a connection through SOCKS4a proxy using an existing stream.
#[doc(hidden)]
pub fn connect_stream<S>(stream: S, destination: Addr) -> IoFuture<S>
    where S: Read + Write + Send + 'static
{
    done({
        let mut buffer = Vec::new();
        write_request(&mut buffer, &destination).and(Ok(buffer))
    }).and_then(move |buffer| {
        write_all(stream, buffer)
    }).and_then(|(stream, mut buffer)| {
        buffer.resize(8, 0);
        read_exact(stream, buffer)
    }).and_then(|(stream, buffer)| {
        if buffer[0] != 0 {
            return Err(invalid_data("proxy: Invalid version in response (not a SOCKS4a proxy?)"))
        }
        match buffer[1] {
            90 => Ok(stream),
            91 => Err(other("proxy: Request rejected or failed")),
            92 => Err(other("proxy: Request rejected becasue SOCKS server cannot connect to identd on the client")),
            93 => Err(other("proxy: Request rejected because the client program and identd report different user-ids")),
            code => Err(other(format!("proxy: Error {}", code))),
        }
    }).boxed()
}

/// Writes a connect request to a given buffer.
fn write_request(buffer: &mut Vec<u8>, destination: &Addr) -> Result<()> {
    try!(buffer.write(&[VERSION, CMD_CONNECT]));
    write_address(buffer, destination)
}

/// Writes an address to a given buffer.
fn write_address(buffer: &mut Vec<u8>, address: &Addr) -> Result<()> {
    match *address {
        Addr::V4(ref sa) => {
            try!(write_port(buffer, sa.port()));
            try!(buffer.write(&sa.ip().octets()));
            try!(buffer.write(&[0]));
            Ok(())
        }
        Addr::V6(..) => {
            Err(invalid_input("proxy: IPv6 addresses are unsupported in SOCKS4a"))
        }
        Addr::Domain(ref da) => {
            if da.domain().len() > 255 || da.domain().contains('\0') {
                return Err(invalid_input("proxy: invalid domain name"));
            }
            try!(write_port(buffer, da.port()));
            try!(buffer.write(&[0, 0, 0, 1]));
            try!(buffer.write(&[0]));
            try!(buffer.write(da.domain().as_bytes()));
            try!(buffer.write(&[0]));
            Ok(())
        }
    }
}

/// Constants used in SOCKS version 4a.
mod consts {
    pub const VERSION: u8 = 4;
    pub const CMD_CONNECT: u8 = 1;
}

#[cfg(test)]
mod tests {

    use address::*;
    use common::test::*;
    use tokio_core::reactor::Core;
    use v4::*;
    use v4::consts::*;

    const RESPONSE_VERSION: u8 = 0;
    const REQUEST_GRANTED: u8 = 90;

    #[test]
    fn connect_ipv4() {
        let stream = Stream::new(&[
            RESPONSE_VERSION, REQUEST_GRANTED,
            8, 1,
            192, 168, 1, 2,
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "1.2.3.4:5".to_addr().unwrap();
        let stream = reactor.run(connect_stream(stream, address)).unwrap();

        assert_eq!([VERSION, CMD_CONNECT,
                    0, 5,
                    1, 2, 3, 4,
                    0],
                    stream.write_buffer());
        assert!(stream.read_all());
    }

    #[test]
    fn connect_ipv6() {
        let stream = Stream::new(&[]);

        let mut reactor = Core::new().unwrap();
        let address = "[::ffff:192.168.0.1]:80".to_addr().unwrap();
        let error = reactor.run(connect_stream(stream, address)).err().unwrap();

        assert_eq!("proxy: IPv6 addresses are unsupported in SOCKS4a", format!("{}", error));
    }

    #[test]
    fn connect_domain() {
        let stream = Stream::new(&[
            RESPONSE_VERSION, REQUEST_GRANTED,
            0, 0,
            0, 0, 0, 0,
        ]);

        let mut reactor = Core::new().unwrap();
        let address = "z.com:80".to_addr().unwrap();
        let stream = reactor.run(connect_stream(stream, address)).unwrap();

        assert_eq!([VERSION, CMD_CONNECT,
                    0, 80,
                    0, 0, 0, 1,
                    0,
                    b'z', b'.', b'c', b'o', b'm', 0],
                    stream.write_buffer());
        assert!(stream.read_all());
    }
}
