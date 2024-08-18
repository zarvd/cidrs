#![deny(
    warnings,
    rust_2018_idioms,
    clippy::map_clone,
    clippy::clone_on_ref_ptr,
    clippy::dbg_macro,
    clippy::enum_glob_use,
    clippy::get_unwrap,
    clippy::macro_use_imports,
    clippy::str_to_string,
    clippy::inefficient_to_string,
    clippy::too_many_lines,
    clippy::or_fun_call
)]

mod cidr;
mod error;

#[cfg(feature = "routing-table")]
mod routing_table;

#[cfg(feature = "routing-table")]
pub use routing_table::{CidrRoutingTable, Ipv4CidrRoutingTable, Ipv6CidrRoutingTable};

pub use cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};
pub use error::{Error, Result};
