#![deny(
    warnings,
    rust_2018_idioms,
    clippy::branches_sharing_code,
    clippy::clear_with_drain,
    clippy::clone_on_ref_ptr,
    clippy::cognitive_complexity,
    clippy::collection_is_never_read,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::enum_glob_use,
    clippy::equatable_if_let,
    clippy::get_unwrap,
    clippy::inefficient_to_string,
    clippy::macro_use_imports,
    clippy::map_clone,
    clippy::map_unwrap_or,
    clippy::needless_collect,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::std_instead_of_core,
    clippy::str_to_string,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::wildcard_imports
)]

mod cidr;
mod error;

mod aggregate;
#[cfg(feature = "routing-table")]
mod routing_table;

pub use aggregate::{aggregate, aggregate_ipv4, aggregate_ipv6, partition_by_ip_family};
pub use cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};
pub use error::{Error, Result};
#[cfg(feature = "routing-table")]
pub use routing_table::{CidrRoutingTable, Ipv4CidrRoutingTable, Ipv6CidrRoutingTable};
