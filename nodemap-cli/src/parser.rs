use std::net::IpAddr;
use std::str::FromStr;
use clap::ArgMatches;
use netscan::setting::ScanType;
use nodemap_core::option;
use nodemap_core::network;
use nodemap_core::option::TargetInfo;
use super::define;
use super::validator;
use super::db;
use super::process;

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
    if process::privileged() {
        opt.port_scan_type = ScanType::TcpSynScan;
    }else{
        opt.port_scan_type = ScanType::TcpConnectScan;
        opt.async_scan = true;
    }
    opt
}

pub fn parse_args(matches: ArgMatches) -> option::ScanOption {
    let mut opt = get_default_option();
    match matches.subcommand() {
        Some(("port", sub_m)) => {
            opt.command_type = option::CommandType::PortScan;
            let target: &str = sub_m.value_of("target").unwrap();
            let socketaddr_vec: Vec<&str> = target.split(":").collect();
            let host: String = socketaddr_vec[0].to_string();
            let mut target_info: TargetInfo = TargetInfo::new();
            if validator::is_ipaddr(host.clone()) {
                target_info.ip_addr = host.parse::<IpAddr>().unwrap();
            }else {
                match dns_lookup::lookup_host(&host) {
                    Ok(addrs) => {
                        for addr in addrs {
                            if addr.is_ipv4() {
                                target_info.ip_addr = addr;
                                target_info.host_name = host.clone();
                                break;
                            }
                        }
                    },
                    Err(_) => {},
                }
            }
            if socketaddr_vec.len() > 1 {
                let port_opt = socketaddr_vec[1].to_string();
                if port_opt.contains("-") {
                    let range: Vec<&str> = port_opt.split("-").collect();
                    let s: u16 = match range[0].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => 0,
                    };
                    let e: u16 = match range[1].parse::<u16>() {
                        Ok(e) => e,
                        Err(_) => 0,
                    };
                    if s != 0 && e != 0 && s < e {
                        target_info.set_dst_ports_from_range(s, e);
                    }
                }else if port_opt.contains(",") {
                    target_info.set_dst_ports_from_csv(port_opt);
                }
            }else{
                opt.default_scan = true;
                target_info.ports = db::get_default_ports();
            }
            opt.targets.push(target_info);
        },
        Some(("host", sub_m)) => {
            opt.command_type = option::CommandType::HostScan;
            let target: &str = sub_m.value_of("target").unwrap();
            let target_vec: Vec<&str> = target.split("/").collect();
            if validator::is_ipaddr(target_vec[0].to_string()) {
                let nw_addr: String = match network::get_network_address(target_vec[0].to_string()) {
                    Ok(nw_addr) => nw_addr,
                    Err(e) => {
                        print!("{}", e);
                        std::process::exit(0);
                    },
                };
                // network
                if target.contains("/") {
                    let nw_vec: Vec<&str> = target.split("/").collect();
                    let prefix_len: u8 = match nw_vec[0].parse::<u8>() {
                        Ok(prefix_len) => prefix_len,
                        Err(_) => 24,
                    };
                    opt.set_dst_hosts_from_na(nw_addr, prefix_len);
                }else{
                    opt.set_dst_hosts_from_na(nw_addr, 24);
                }
            }else{
                // list
                match validator::validate_filepath(target) {
                    Ok(_) => {
                        opt.set_dst_hosts_from_list(target.to_string());
                    },
                    Err(_) => {
                        let ip_vec: Vec<&str> = target.split(",").collect();
                        for ip_str in ip_vec {
                            match IpAddr::from_str(&ip_str) {
                                Ok(ip) => {
                                    opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                                },
                                Err(_) => {
                                    if let Some(ip) = network::lookup_host_name(ip_str.to_string()) {
                                        opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                                    }
                                },
                            }
                        }
                    },
                }
            }
        },
        Some(("ping", sub_m)) => {
            opt.command_type = option::CommandType::Ping;
            let target: &str = sub_m.value_of("target").unwrap();
            match target.parse::<IpAddr>(){
                Ok(ip) => {
                    opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                },
                Err(_) => {},
            }
        },
        Some(("trace", sub_m)) => {
            opt.command_type = option::CommandType::Traceroute;
            let target: &str = sub_m.value_of("target").unwrap();
            match target.parse::<IpAddr>(){
                Ok(ip) => {
                    opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                },
                Err(_) => {},
            }
        },
        Some(("domain", sub_m)) => {
            opt.command_type = option::CommandType::DomainScan;
            let base_domain: &str = sub_m.value_of("base_domain").unwrap();
            opt.targets.push(TargetInfo::new_with_base_domain(base_domain.to_string()));
        },
        Some(("uri", sub_m)) => {
            opt.command_type = option::CommandType::UriScan;
            let base_uri: &str = sub_m.value_of("base_uri").unwrap();
            opt.targets.push(TargetInfo::new_with_base_uri(base_uri.to_string()));
        },
        Some(("batch", _sub_m)) => {
            opt.command_type = option::CommandType::BatchScan;

        },
        Some(("passive", _sub_m)) => {
            opt.command_type = option::CommandType::PassiveScan;
            
        },
        _ => {},
    }
    opt
}
