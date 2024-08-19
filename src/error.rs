use core::fmt;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CidrParseKind {
    Ip,
    Ipv4,
    Ipv6,
}

impl fmt::Display for CidrParseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrParseKind::Ip => write!(f, "IP"),
            CidrParseKind::Ipv4 => write!(f, "IPv4"),
            CidrParseKind::Ipv6 => write!(f, "IPv6"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("overflow IPv4 CIDR bit: {0}")]
    OverflowIpv4CidrBit(u8),
    #[error("overflow IPv6 CIDR bit: {0}")]
    OverflowIpv6CidrBit(u8),
    #[error("invalid CIDR syntax: {0}")]
    CidrParseError(CidrParseKind),
}

pub type Result<T> = core::result::Result<T, Error>;
