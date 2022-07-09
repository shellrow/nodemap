use clap::ArgMatches;
use nodemap_core::option;

pub fn parse_port_args(_matches: ArgMatches) -> option::ScanOption {
    option::ScanOption::new()
}
