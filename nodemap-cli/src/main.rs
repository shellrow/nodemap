#[macro_use]
extern crate clap;

mod define;
mod validator;
mod parser;

use std::env;
use chrono::{Local, DateTime};
use clap::{Command, AppSettings, Arg, ArgGroup};

use nodemap_core::{option, process, sys};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    let opt: option::ScanOption = parser::parse_port_args(matches);
    match opt.exec_type {
        option::ExecType::PortScan => {
            match opt.port_scan_type {
                netscan::setting::ScanType::TcpSynScan => {
                    if !process::privileged() {
                        
                    }
                },
                _ => {},
            }
        },
        option::ExecType::HostScan => {},
        option::ExecType::Ping => {},
        option::ExecType::Traceroute => {},
        option::ExecType::UriScan => {},
        option::ExecType::DomainScan => {},
        option::ExecType::BatchScan => {},
        option::ExecType::PassiveScan => {},
    }
    show_banner_with_starttime();
    exit_with_error_message("test");
}

fn get_app_settings<'a>() -> Command<'a> {
    let app = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::new("port")
            .help("Scan ports of the specified host. \nUse default port list if port range omitted. \nExamples \n-p 192.168.1.8 -s -O \n-p 192.168.1.8:1-1000 \n-p 192.168.1.8:22,80,8080 \n-p 192.168.1.8 -l custom-list.txt")
            .short('p')
            .long("port")
            .takes_value(true)
            .value_name("ip_addr:port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::new("network")
            .help("Scan hosts in specified network \nExample: -n 192.168.1.0")
            .short('n')
            .long("network")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_network_opt)
        )
        .arg(Arg::new("host")
            .help("Scan hosts in specified host-list \nExample: \n-H custom-list.txt \n-H 192.168.1.10,192.168.1.20,192.168.1.30")
            .short('H')
            .long("host")
            .takes_value(true)
            .value_name("host_list")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::new("ping")
            .help("Ping to specified host")
            .long("ping")
            .takes_value(false)
            .value_name("host")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::new("trace")
            .help("Traceroute to specified host")
            .long("trace")
            .takes_value(false)
            .value_name("host")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::new("uri")
            .help("URI scan")
            .short('u')
            .long("uri")
            .takes_value(false)
            .value_name("base_uri")
            .validator(validator::validate_uri_opt)
        )
        .arg(Arg::new("domain")
            .help("Domain scan")
            .short('d')
            .long("domain")
            .takes_value(false)
            .value_name("base_domain")
            .validator(validator::validate_domain_opt)
        )
        .arg(Arg::new("timeout")
            .help("Set timeout in ms - Ex: -t 10000")
            .short('t')
            .long("timeout")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_timeout)
        )
        .arg(Arg::new("waittime")
            .help("Set waittime in ms (default:100ms) - Ex: -w 200")
            .short('w')
            .long("waittime")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::new("rate")
            .help("Set sendrate in ms - Ex: -r 1")
            .short('r')
            .long("rate")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::new("count")
            .help("Set number of requests or pings to be sent")
            .short('c')
            .long("count")
            .takes_value(true)
            .value_name("count")
            .validator(validator::validate_count)
        )
        .arg(Arg::new("ttl")
            .help("Set TTL for ping or traceroute")
            .short('m')
            .long("ttl")
            .takes_value(true)
            .value_name("ttl")
            .validator(validator::validate_ttl)
        )
        .arg(Arg::new("portscantype")
            .help("Set port scan type (default:SYN) - SYN, CONNECT")
            .short('P')
            .long("portscantype")
            .takes_value(true)
            .value_name("scantype")
            .validator(validator::validate_portscantype)
        )
        .arg(Arg::new("async")
            .help("Perform asynchronous scan")
            .short('A')
            .long("async")
            .takes_value(false)
        )
        .arg(Arg::new("service")
            .help("Enable service detection")
            .short('S')
            .long("service")
            .takes_value(false)
        )
        .arg(Arg::new("OS")
            .help("Enable OS detection")
            .short('O')
            .long("os")
            .takes_value(false)
        )
        .arg(Arg::new("interface")
            .help("Specify network interface by IP address - Ex: -i 192.168.1.4")
            .short('i')
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::new("list")
            .help("Use list - Ex: -l custom-list.txt")
            .short('l')
            .long("list")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_filepath)
        )
        .arg(Arg::new("output")
            .help("Save scan result in json format - Ex: -o result.json")
            .short('o')
            .long("output")
            .takes_value(true)
            .value_name("file_path")
        )
        .arg(Arg::new("acceptinvalidcerts")
            .help("Accept invalid certs (This introduces significant vulnerabilities)")
            .long("acceptinvalidcerts")
            .takes_value(false)
        )
        .group(ArgGroup::new("mode")
            .args(&["port", "network", "host", "ping", "trace", "uri", "domain"])
        )
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), define::CRATE_UPDATE_DATE, sys::get_os_type());
    println!("{}", crate_description!());
    println!("{}", crate_authors!());
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}

fn show_banner_with_starttime() {
    println!("{} {} {}", crate_name!(), crate_version!(), sys::get_os_type());
    println!("{}", define::CRATE_REPOSITORY);
    println!();
    let local_datetime: DateTime<Local> = Local::now();
    println!("Scan started at {}", local_datetime);
    println!();
}

fn exit_with_error_message(message: &str) {
    println!();
    println!("Error: {}", message);
    std::process::exit(0);
}
