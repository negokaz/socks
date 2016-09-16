// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

use address::Addr;
use address::ToAddr;
use futures::Future;
use futures::done;
use protocol::*;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use tokio_core::io::read_exact;
use tokio_core::io::write_all;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;

/// Crates a new connection through a SOCKS4a proxy.
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
pub fn connect_stream<S>(stream: S, destination: Addr) -> IoFuture<S>
    where S: Read + Write + 'static
{
    Box::new(done({
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
    }))
}

fn write_request(buffer: &mut Vec<u8>, destination: &Addr) -> Result<()> {
    try!(buffer.write(&[VERSION, CMD_CONNECT]));
    write_address(buffer, destination)
}

fn write_address(buffer: &mut Vec<u8>, address: &Addr) -> Result<()> {
    match *address {
        Addr::V4(ref sa) => {
            try!(write_port(buffer, sa.port()));
            try!(buffer.write(&sa.ip().octets()));
            Ok(())
        }
        Addr::V6(..) => {
            Err(invalid_input("proxy: IPv6 addresses are unsupported in SOCKS4a"))
        }
        Addr::Domain(ref da) => {
            // TODO check for null?
            try!(write_port(buffer, da.port()));
            try!(buffer.write(&[0, 0, 0, 1]));
            try!(buffer.write(da.domain().as_bytes()));
            try!(buffer.write(&[0]));
            Ok(())
        }
    }
}

pub const VERSION: u8 = 4;
pub const CMD_CONNECT: u8 = 1;

