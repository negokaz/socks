// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use futures::Future;
use std::error;
use std::io::ErrorKind;
use std::io;
use std::io::Result;

pub type IoFuture<T> = Box<Future<Item=T, Error=io::Error>>;

/// Returns a new error of other kind.
pub fn other<E>(error: E) -> io::Error
    where E: Into<Box<error::Error + Send + Sync>>
{
    io::Error::new(ErrorKind::Other, error)
}

/// Returns a new error of invalid input kind.
pub fn invalid_input<E>(error: E) -> io::Error
    where E: Into<Box<error::Error + Send + Sync>>
{
    io::Error::new(ErrorKind::InvalidInput, error)
}

/// Returns a new error of invalid data kind.
pub fn invalid_data<E>(error: E) -> io::Error
    where E: Into<Box<error::Error + Send + Sync>>
{
    io::Error::new(ErrorKind::InvalidData, error)
}

/// Writes a port in network byte order.
pub fn write_port(buffer: &mut Vec<u8>, port: u16) -> Result<()> {
    buffer.write_u16::<BigEndian>(port)
}

