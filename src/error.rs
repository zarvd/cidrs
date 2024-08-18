#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid mask: expected {min} <= mask <= {max}, but got {actual}")]
    InvalidMask { min: u8, max: u8, actual: u8 },
    #[error("invalid CIDR syntax")]
    ParseError,
}
