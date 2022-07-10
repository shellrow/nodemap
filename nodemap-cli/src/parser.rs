use std::net::IpAddr;

use clap::ArgMatches;
use nodemap_core::option;
use super::define;

fn get_default_option() -> option::ScanOption {
    let mut opt = option::ScanOption::new();
    opt.src_port = define::DEFAULT_SRC_PORT;
    match default_net::get_default_interface() {
        Ok(interface) => {
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            }else{
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        },
        Err(_) => {},
    }
    opt
}

pub fn parse_args(_matches: ArgMatches) -> option::ScanOption {
    let mut opt = get_default_option();
    opt.src_port = define::DEFAULT_SRC_PORT;
    opt
}
