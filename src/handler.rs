use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use std::collections::HashMap;
use std::net::IpAddr;
use netscan::result::{HostScanResult as NsHostScanResult, ScanStatus};
use nodemap_core::result::PingStat;
use nodemap_core::{option, scan, result, network, define};
use console::{Style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};
use super::db;

fn get_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    let ps: ProgressStyle = ProgressStyle::default_spinner()
        .template("{spinner:.blue} {msg}")
        .tick_strings(&[
            "⠋",
			"⠙",
			"⠹",
			"⠸",
			"⠼",
			"⠴",
			"⠦",
			"⠧",
			"⠇",
			"⠏",
            "✓",
        ]);
    pb.set_style(ps);
    pb
}

pub async fn handle_port_scan(opt: option::ScanOption) {
    let mut result: result::PortScanResult = result::PortScanResult::new();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(opt, &msg_tx).await
        })
    });
    let mut pb = get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_PORTSCAN => {pb.set_message("Scanning ports ...");},
                define::MESSAGE_END_PORTSCAN => {pb.finish_with_message("Port scan"); pb = get_spinner();},
                define::MESSAGE_START_SERVICEDETECTION => {pb.set_message("Detecting services ...");},
                define::MESSAGE_END_SERVICEDETECTION => {pb.finish_with_message("Service detection"); pb = get_spinner();},
                define::MESSAGE_START_OSDETECTION => {pb.set_message("Detecting OS ...");},
                define::MESSAGE_END_OSDETECTION => {pb.finish_with_message("OS detection"); pb = get_spinner();},
                _ => {},
            }
        }
    }
    pb.finish_and_clear();
    result = handle.join().unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

pub async fn handle_host_scan(opt: option::ScanOption) {
    let mut result: result::HostScanResult = result::HostScanResult::new();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let h_opt = opt.clone();
    let handle = thread::spawn(move|| {
        if h_opt.async_scan {
            async_io::block_on(async {
                scan::run_async_host_scan(h_opt, &msg_tx).await
            })
        }else{
            scan::run_host_scan(h_opt, &msg_tx)
        }
    });

    let pb = get_spinner();
    pb.set_message("Scanning hosts ...");
    while let Ok(_msg) = msg_rx.recv() {

    }
    let hs_result: NsHostScanResult = handle.join().unwrap();

    pb.finish_and_clear();

    match hs_result.scan_status {
        ScanStatus::Done => {
            println!("Host scan ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
        },
        ScanStatus::Timeout => {
            println!("Host scan ... {} {}", Emoji::new("⌛", ""),Style::new().yellow().apply_to("Timedout"));
        },
        _ => {
            println!("Host scan ... {} {}", Emoji::new("❌", ""),Style::new().green().apply_to("Error"));
        },
    }

    let oui_map = db::get_oui_map();
    let ttl_map: HashMap<u8, String> = db::get_os_ttl();
    let mac_map: HashMap<IpAddr, String> = network::get_mac_addresses(hs_result.get_hosts(), opt.src_ip);
    for host in hs_result.hosts{
        let host_info = result::HostInfo {
            ip_addr: host.ip_addr.to_string(),
            host_name: dns_lookup::lookup_addr(&host.ip_addr).unwrap_or(String::new()),
            mac_addr: mac_map.get(&host.ip_addr).unwrap_or(&String::new()).to_string(),
            vendor_info: if let Some(mac) = mac_map.get(&host.ip_addr){
                if mac.len() > 16 {
                    let prefix8 = mac[0..8].to_uppercase();
                    oui_map.get(&prefix8).unwrap_or(&String::new()).to_string()
                }else{
                    oui_map.get(mac).unwrap_or(&String::new()).to_string()
                }
            }else{String::new()},
            os_name: ttl_map.get(&host.ttl).unwrap_or(&String::new()).to_string(),
            cpe: String::new(),
        };
        result.hosts.push(host_info);
    }

    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));

}

pub fn handle_ping(opt: option::ScanOption) {    
    //let mut result: result::PingStat = result::PingStat::new();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let ping_opt = opt.clone();
    let handle = thread::spawn(move||{
        scan::run_ping(ping_opt, &msg_tx)
    });
    //let pb = get_spinner();
    //pb.set_message("Ping probe ...");
    while let Ok(msg) = msg_rx.recv() {
        println!("{}", msg);
    }
    let result: PingStat = handle.join().unwrap();
    //pb.finish_and_clear();
    //println!("Ping ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

pub fn handle_trace(opt: option::ScanOption) {
    
}

pub fn handle_domain_scan(opt: option::ScanOption) {
    
}

pub fn handle_uri_scan(opt: option::ScanOption) {
    
}
