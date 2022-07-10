#[macro_use]
extern crate clap;

mod define;
mod validator;
mod parser;

use std::env;
use chrono::{Local, DateTime};
use clap::{Command, AppSettings, Arg, App};

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
    // SubCommand
    let sc_port: App = App::new("port")
        .about("Scan ports of the specified host. \nUse default port list if port range omitted. \nExamples: \nport 192.168.1.8 -S -O \nport 192.168.1.8:1-1000 \nport 192.168.1.8:22,80,8080 \nport 192.168.1.8 -l custom-list.txt")
        .arg(Arg::new("target")
        .required(true)
        .validator(validator::validate_port_opt));
    let sc_host: App = App::new("host")
        .about("Scan hosts in specified network or host-list. \nExamples: \nhost 192.168.1.0 \nhost custom-list.txt \nhost 192.168.1.10,192.168.1.20,192.168.1.30")
        .arg(Arg::new("target")
        .required(true)
        .validator(validator::validate_host_opt));
    let sc_ping: App = App::new("ping")
        .about("Ping to specified host. \nExamples: \nping 192.168.1.8 -c 4")
        .arg(Arg::new("target")
        .required(true)
        .validator(validator::validate_host_opt));
    let sc_trace: App = App::new("trace")
        .about("Traceroute to specified host. \nExamples: \ntrace 192.168.1.8")
        .arg(Arg::new("target")
        .required(true)
        .validator(validator::validate_host_opt));
    let sc_uri: App = App::new("uri")
        .about("URI scan. \nExamples: \nuri https://example.com/")
        .arg(Arg::new("base_uri")
        .required(true)
        .validator(validator::validate_uri_opt));
    let sc_domain: App = App::new("domain")
        .about("Domain scan. \nExamples: \ndomain example.com")
        .arg(Arg::new("base_domain")
        .required(true)
        .validator(validator::validate_domain_opt));
    let sc_batch: App = App::new("batch")
        .about("Batch scan with config. \nExamples: \nbatch <path_to_config_file>")
        .arg(Arg::new("config")
        .required(true)
        .validator(validator::validate_filepath));
    let sc_passive: App = App::new("passive")
        .about("Passive scan. \nExamples: \npassive shodan")
        .arg(Arg::new("target")
        .required(true)
        .validator(validator::validate_domain_opt));

    let app: App = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(sc_port)
        .subcommand(sc_host)
        .subcommand(sc_ping)
        .subcommand(sc_trace)
        .subcommand(sc_uri)
        .subcommand(sc_domain)
        .subcommand(sc_batch)
        .subcommand(sc_passive)
        .arg(Arg::new("interface")
            .help("Specify the network interface")
            .short('i')
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::new("source")
            .help("Specify the source IP address")
            .short('s')
            .long("source")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_interface)
        )
        .arg(Arg::new("protocol")
            .help("Specify the protocol")
            .short('p')
            .long("protocol")
            .takes_value(true)
            .value_name("protocol")
            .validator(validator::validate_portscantype)
        )
        .arg(Arg::new("maxhop")
            .help("Set max hop(TTL) for ping or traceroute")
            .short('m')
            .long("maxhop")
            .takes_value(true)
            .value_name("maxhop")
            .validator(validator::validate_ttl)
        )
        .arg(Arg::new("scantype")
            .help("Specify the scantype")
            .short('T')
            .long("scantype")
            .takes_value(true)
            .value_name("scantype")
            .validator(validator::validate_portscantype)
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
        .arg(Arg::new("service")
            .help("Enable service detection")
            .short('S')
            .long("service")
            .takes_value(false)
        )
        .arg(Arg::new("os")
            .help("Enable OS detection")
            .short('O')
            .long("os")
            .takes_value(false)
        )
        .arg(Arg::new("async")
            .help("Perform asynchronous scan")
            .short('A')
            .long("async")
            .takes_value(false)
        )
        .arg(Arg::new("list")
            .help("Use list - Ex: -l custom-list.txt")
            .short('l')
            .long("list")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_filepath)
        )
        .arg(Arg::new("config")
            .help("Use config file")
            .short('C')
            .long("config")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_filepath)
        )
        .arg(Arg::new("datasource")
            .help("Specify the datasource")
            .short('d')
            .long("datasource")
            .takes_value(false)
            .value_name("datasource_name")
            .validator(validator::validate_domain_opt)
        )
        .arg(Arg::new("save")
            .help("Save scan result in json format - Ex: -o result.json")
            .short('o')
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .arg(Arg::new("acceptinvalidcerts")
            .help("Accept invalid certs (This introduces significant vulnerabilities)")
            .long("acceptinvalidcerts")
            .takes_value(false)
        )
        //.group(ArgGroup::new("mode").args(&["network", "host", "ping", "trace", "uri", "domain"]))
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
