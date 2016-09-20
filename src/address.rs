// Copyright 2016 Tomasz Miąsko
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option. You may not use
// this file except according to those terms.

use std::fmt;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::str::FromStr;
use tokio_dns::Endpoint;
use tokio_dns::ToEndpoint;

/// A domain address which is a (domain name, port) combination.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct DomainAddr {
    domain: String,
    port: u16
}

impl DomainAddr {
    /// Creates a new domain address from a domain name and a port.
    ///
    /// Note that domain name is not validated in any way.
    pub fn new(domain: &str, port: u16) -> DomainAddr {
        DomainAddr { domain: domain.to_owned(), port: port }
    }

    /// Returns the domain name associated with this address.
    pub fn domain(&self) -> &str { &self.domain }

    /// Changes the domain name assocaited with this address.
    pub fn set_domain(&mut self, domain: String) { self.domain = domain; }

    /// Returns the port number associated with this address.
    pub fn port(&self) -> u16 { self.port }

    /// Changes the port number associated with this address.
    pub fn set_port(&mut self, port: u16) { self.port = port; }
}

impl fmt::Display for DomainAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.domain, self.port)
    }
}

/// Representation of an address for use with SOCKS proxy.
///
/// An address can represent an IPv4 address, an IPv64 address, or a domain
/// name paired together with a port number.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Addr {
    /// An IPv4 socket address
    V4(SocketAddrV4),
    /// An IPv6 socket address
    V6(SocketAddrV6),
    /// A domain address
    Domain(DomainAddr)
}

impl Addr {
    /// Returns the port number associated with this address.
    pub fn port(&self) -> u16 {
        match *self {
            Addr::V4(ref addr) => addr.port(),
            Addr::V6(ref addr) => addr.port(),
            Addr::Domain(ref addr) => addr.port(),
        }
    }

    /// Changes the port number associated with this address.
    pub fn set_port(&mut self, port: u16) {
        match *self {
            Addr::V4(ref mut addr) => addr.set_port(port),
            Addr::V6(ref mut addr) => addr.set_port(port),
            Addr::Domain(ref mut addr) => addr.set_port(port),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Addr::V4(ref addr) => addr.fmt(f),
            Addr::V6(ref addr) => addr.fmt(f),
            Addr::Domain(ref addr) => addr.fmt(f),
        }
    }
}

impl FromStr for DomainAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<DomainAddr> {
        let i = try!(s.rfind(':').ok_or_else(|| invalid_address(s)));
        let host = &s[..i];
        let port = &s[i+1..];
        let port = try!(u16::from_str(port).map_err(|_| invalid_address(s)));
        Ok(DomainAddr::new(host, port))
    }
}

impl FromStr for Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Addr> {
        if let Ok(addr) = SocketAddrV4::from_str(s) {
            return Ok(Addr::V4(addr));
        } else if let Ok(addr) = SocketAddrV6::from_str(s) {
            return Ok(Addr::V6(addr));
        } else if let Ok(addr) = DomainAddr::from_str(s) {
            return Ok(Addr::Domain(addr));
        } else {
            return Err(invalid_address(s));
        }
    }
}

fn invalid_address(s: &str) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!("invalid address: {}", s))
}


/// A trait for objects which can be converted to address as used by SOCKS
/// protocol.
/// 
/// By default is implemented for the following types:
///
///  * `SocketAddr`, `SocketAddrV4`, `SocketAddrV6`, `DomainAddr` implemented
///    trivially.
///
///  * `(&str, u16)` - the string should be either a representation of an IP
///    address as expected by `FromStr` implementation for `IpvNAddr` or
///    a host name.
///
///  * `&str` - the string should be either a string representation of a
///    `SocketAddr` as expected by its `FromStr` implementation or a string
///    `<hostname>:<port>` pair where `<port>` is a `u16` value.
///
pub trait ToAddr {
    /// Converts this object into an `Addr` or returns an error.
    fn to_addr(&self) -> Result<Addr>;
}

impl ToAddr for Addr {
    fn to_addr(&self) -> Result<Addr> {
        Ok(self.clone())
    }
}

impl ToAddr for SocketAddr {
    fn to_addr(&self) -> Result<Addr> {
        match *self {
            SocketAddr::V4(addr) => Ok(Addr::V4(addr)),
            SocketAddr::V6(addr) => Ok(Addr::V6(addr)),
        }
    }
}

impl ToAddr for SocketAddrV4 {
    fn to_addr(&self) -> Result<Addr> {
        Ok(Addr::V4(*self))
    }
}

impl ToAddr for SocketAddrV6 {
    fn to_addr(&self) -> Result<Addr> {
        Ok(Addr::V6(*self))
    }
}

impl ToAddr for DomainAddr {
    fn to_addr(&self) -> Result<Addr> {
        Ok(Addr::Domain(self.clone()))
    }
}

impl<'a> ToAddr for (&'a str, u16) {
    fn to_addr(&self) -> Result<Addr> {
        Ok(Addr::Domain(DomainAddr::new(self.0, self.1)))
    }
}

impl<'a> ToAddr for (&'a str) {
    fn to_addr(&self) -> Result<Addr> {
        Addr::from_str(self)
    }
}

#[doc(hidden)]
/// Converts an address to an endpoint as used by tokio-dns crate.
///
/// This is an implementation detail. Presence of `ToEndpoint` implementation
/// for `Addr should not be relied upon.
impl<'a> ToEndpoint<'a> for &'a Addr {
    fn to_endpoint(self) -> Result<Endpoint<'a>> {
        let endpoint = match *self {
            Addr::Domain(ref da) => Endpoint::Host(da.domain(), da.port()),
            Addr::V4(sa) => Endpoint::SocketAddr(SocketAddr::V4(sa)),
            Addr::V6(sa) => Endpoint::SocketAddr(SocketAddr::V6(sa)),
        };
        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use address::*;
    use std::net::*;
    use std::str::FromStr;

    #[test]
    fn to_addr_from_socket_addr() {
        let ipv4 = SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 0),
            1234);
        let ipv6 = SocketAddrV6::new(
            Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
            9090, 0, 0);
        let sockv4 = SocketAddr::V4(ipv4);
        let sockv6 = SocketAddr::V6(ipv6);

        assert_eq!(Addr::V4(ipv4), ipv4.to_addr().unwrap());
        assert_eq!(Addr::V6(ipv6), ipv6.to_addr().unwrap());
        assert_eq!(Addr::V4(ipv4), sockv4.to_addr().unwrap());
        assert_eq!(Addr::V6(ipv6), sockv6.to_addr().unwrap());
    }

    #[test]
    fn to_addr_from_domain_addr() {
        let domain = DomainAddr::new("example.com", 80);
        assert_eq!(Addr::Domain(domain.clone()), domain.to_addr().unwrap());
    }

    #[test]
    fn to_addr_from_str_port_pair() {
        assert_eq!(
            Addr::Domain(DomainAddr::new("example.com", 80)),
            ("example.com", 80).to_addr().unwrap());
    }

    #[test]
    fn to_addr_from_str() {
        assert_eq!(
            Addr::Domain(DomainAddr::new("example.com", 80)),
            "example.com:80".to_addr().unwrap());
    }

    #[test]
    fn from_str_for_addr() {
        assert_eq!(
            Addr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 8080)),
            Addr::from_str("192.168.0.2:8080").unwrap());
        assert_eq!(
            Addr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 9090, 0, 0)),
            Addr::from_str("[::1]:9090").unwrap());
        assert_eq!(
            Addr::Domain(DomainAddr::new("example.com", 80)),
            Addr::from_str("example.com:80").unwrap());
        assert!(Addr::from_str("not an address").is_err());
    }

    #[test]
    fn display() {
        assert_eq!(
            "example.com:1234",
            format!("{}", Addr::Domain(DomainAddr::new("example.com", 1234))));
    }
}
