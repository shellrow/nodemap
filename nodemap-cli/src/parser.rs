use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use clap::ArgMatches;
use netscan::setting::ScanType;
use nodemap_core::option;
use nodemap_core::network;
use nodemap_core::option::Protocol;
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
    // Mode
    if matches.contains_id("port") {
        opt.command_type = option::CommandType::PortScan;
        let target: &str = matches.value_of("port").unwrap();
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
    }else if matches.contains_id("host") {
        opt.command_type = option::CommandType::HostScan;
        opt.protocol = option::Protocol::ICMPv4;
        let target: &str = matches.value_of("host").unwrap();
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
    }else if matches.contains_id("ping") {
        opt.command_type = option::CommandType::Ping;
        let target: &str = matches.value_of("ping").unwrap();
        match target.parse::<IpAddr>(){
            Ok(ip) => {
                opt.targets.push(TargetInfo::new_with_ip_addr(ip));
            },
            Err(_) => {},
        }
    }else if matches.contains_id("trace") {
        opt.command_type = option::CommandType::Traceroute;
        let target: &str = matches.value_of("trace").unwrap();
        match target.parse::<IpAddr>(){
            Ok(ip) => {
                opt.targets.push(TargetInfo::new_with_ip_addr(ip));
            },
            Err(_) => {},
        }
    }else if matches.contains_id("uri") {
        opt.command_type = option::CommandType::UriScan;
        let base_uri: &str = matches.value_of("base_uri").unwrap();
        opt.targets.push(TargetInfo::new_with_base_uri(base_uri.to_string()));
    }else if matches.contains_id("domain") {
        opt.command_type = option::CommandType::DomainScan;
        let base_domain: &str = matches.value_of("base_domain").unwrap();
        opt.targets.push(TargetInfo::new_with_base_domain(base_domain.to_string()));
    }else if matches.contains_id("batch") {
        opt.command_type = option::CommandType::BatchScan;
    }else if matches.contains_id("passive") {
        opt.command_type = option::CommandType::PassiveScan;
    }
    // Flags
    if matches.contains_id("interface") {
        let v_interface: String = matches.get_one::<String>("interface").unwrap().to_string();
        if let Some(interface) = nodemap_core::network::get_interface_by_name(v_interface){
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            }else{
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        }
    }
    if matches.contains_id("source") {
        let v_src_ip: String = matches.get_one::<String>("source").unwrap().to_string();
        match v_src_ip.parse::<IpAddr>() {
            Ok(ip_addr) => {
                opt.src_ip = ip_addr;
            },
            Err(_) => {},
        }
    }
    if matches.contains_id("protocol") {
        let v_protocol: String = matches.get_one::<String>("protocol").unwrap().to_string();
        if v_protocol == "TCP" || v_protocol == "tcp" {
            opt.protocol = Protocol::TCP;   
        }else if v_protocol == "UDP" || v_protocol == "udp" {
            opt.protocol = Protocol::UDP;
        }else if v_protocol == "ICMPv4" || v_protocol == "icmpv4" {
            opt.protocol = Protocol::ICMPv4;
        }else if v_protocol == "ICMPv6" || v_protocol == "icmpv6" {
            opt.protocol = Protocol::ICMPv6;
        }
    }
    if matches.contains_id("maxhop") {
        let v_maxhop: String = matches.get_one::<String>("maxhop").unwrap().to_string();
        match v_maxhop.parse::<u8>() {
            Ok(maxhop) => {
                opt.max_hop = maxhop;
            },
            Err(_) => {},
        }
    }
    if matches.contains_id("scantype") {
        let v_scantype: String = matches.get_one::<String>("scantype").unwrap().to_string();
        if v_scantype == "SYN" || v_scantype == "syn" {
            opt.port_scan_type = ScanType::TcpSynScan;   
        }else if v_scantype == "CONNECT" || v_scantype == "connect" {
            opt.port_scan_type = ScanType::TcpConnectScan;
        }else if v_scantype == "ICMPv4" || v_scantype == "icmpv4" {
            opt.host_scan_type = ScanType::IcmpPingScan;
        }else if v_scantype == "ICMPv6" || v_scantype == "icmpv6" {
            opt.host_scan_type = ScanType::IcmpPingScan;
        }else if v_scantype == "TCP" || v_scantype == "tcp" {
            opt.host_scan_type = ScanType::TcpPingScan;
        }else if v_scantype == "UDP" || v_scantype == "udp" {
            opt.host_scan_type = ScanType::UdpPingScan;
        }
    }
    if matches.contains_id("timeout") {
        let v_timeout: u64 = *matches.get_one::<u64>("timeout").unwrap();
        opt.timeout = Duration::from_millis(v_timeout);
    }
    if matches.contains_id("waittime") {
        let v_waittime: u64 = *matches.get_one::<u64>("waittime").unwrap();
        opt.wait_time = Duration::from_millis(v_waittime);
    }
    if matches.contains_id("rate") {
        let v_rate: u64 = *matches.get_one::<u64>("rate").unwrap();
        opt.send_rate = Duration::from_millis(v_rate);
    }
    if matches.contains_id("count") {
        let v_count: u32 = *matches.get_one::<u32>("count").unwrap();
        opt.count = v_count;
    }
    if matches.contains_id("service") {
        opt.service_detection = true;
    }
    if matches.contains_id("os") {
        opt.os_detection = true;
    }
    if matches.contains_id("async") {
        opt.async_scan = true;
    }
    if matches.contains_id("list") {
        let v_list: String = matches.get_one::<String>("list").unwrap().to_string();
        opt.use_wordlist = true;
        opt.wordlist_path = v_list;
    }
    if matches.contains_id("config") {
        let v_config: String = matches.get_one::<String>("config").unwrap().to_string();
        opt.use_config = true;
        opt.config_path = v_config;     
    }
    if matches.contains_id("save") {
        let v_save: String = matches.get_one::<String>("save").unwrap().to_string();
        opt.save_file_path = v_save;
    }
    if matches.contains_id("acceptinvalidcerts") {
        opt.accept_invalid_certs = true;
    }

    opt

}
