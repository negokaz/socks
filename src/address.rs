use std::io::Result;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

// TODO implement Display and FromStr for TargetAddr

/// A domain address which is a (domain name, port) combination.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct DomainAddr {
    domain: String,
    port: u16
}

impl DomainAddr {
    /// Creates a new domain address from a domain name and a port.
    pub fn new(domain: String, port: u16) -> DomainAddr {
        DomainAddr { domain: domain, port: port }
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

/// Representation of an address for use with SOCKS proxy.
///
/// An address can either represent the IPv4 or IPv64 address or a domain name
/// paired together with a port number.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Addr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(DomainAddr)
}

impl Addr {
    /// Returns the port number associated with this address.
    pub fn port(&self) -> u16 {
        match *self {
            Addr::V4(ref addr)     => addr.port(),
            Addr::V6(ref addr)     => addr.port(),
            Addr::Domain(ref addr) => addr.port(),
        }
    }

    /// Changes the port number associated with this address.
    pub fn set_port(&mut self, port: u16) {
        match *self {
            Addr::V4(ref mut addr)     => addr.set_port(port),
            Addr::V6(ref mut addr)     => addr.set_port(port),
            Addr::Domain(ref mut addr) => addr.set_port(port),
        }
    }
}

/// A trait for objects which can be converted to `Addr`.
/// 
/// By default is implemented for the following types:
///
///  * `SocketAddr`, `SocketAddrV4`, `SocketAddrV6`, `DomainAddr` implemented
///    trivially.
///
///  * `(&str, u16)` - the string should be either a string representation of
///    an IP address as expected by `FromStr` implementation for `IpvNAddr` or
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
}
