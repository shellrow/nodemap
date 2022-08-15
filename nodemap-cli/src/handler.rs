use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use netscan::os::ProbeResult;
use netscan::result::{PortScanResult as NsPortScanResult, HostScanResult as NsHostScanResult, ScanStatus};
use netscan::service::PortDatabase;
use nodemap_core::option::TargetInfo;
use nodemap_core::{option, scan, result, network};
use console::{Style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};
use crate::model::TCPFingerprint;
use super::os;
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
    //let term = Term::stdout();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    // Port Scan
    let p_opt = opt.clone();
    let handle = thread::spawn(move|| {
        if p_opt.async_scan {
            async_io::block_on(async {
                scan::run_async_port_scan(p_opt, &msg_tx).await
            })
        }else{
            scan::run_port_scan(p_opt, &msg_tx)
        }
    });

    let pb = get_spinner();
    pb.set_message("Scanning ports ...");
    while let Ok(_msg) = msg_rx.recv() {

    }
    let ps_result: NsPortScanResult = handle.join().unwrap();

    pb.finish_and_clear();
    
    match ps_result.scan_status {
        ScanStatus::Done => {
            println!("Port scan ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
        },
        ScanStatus::Timeout => {
            println!("Port scan ... {} {}", Emoji::new("⌛", ""),Style::new().yellow().apply_to("Timedout"));
        },
        _ => {
            println!("Port scan ... {} {}", Emoji::new("❌", ""),Style::new().green().apply_to("Error"));
        },
    }

    // Service Detection
    let mut sd_result: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    let mut sd_time: Duration = Duration::from_millis(0);
    if opt.service_detection && ps_result.result_map.keys().len() > 0 {
        let mut sd_targets: Vec<TargetInfo> = vec![];
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        sd_targets.push(target);
        let port_db: PortDatabase = PortDatabase { http_ports: db::get_http_ports(), https_ports: db::get_https_ports() };
        let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
        let pb = get_spinner();
        pb.set_message("Detecting services ...");
        let start_time: Instant = Instant::now();
        let handle = thread::spawn(move || {
            scan::run_service_detection(sd_targets, &msg_tx, Some(port_db))
        });
        while let Ok(_msg) = msg_rx.recv() {
            
        }
        pb.finish_and_clear();
        sd_result = handle.join().unwrap();
        sd_time = Instant::now().duration_since(start_time);
        println!("Service detection ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
    }

    // OS Detection
    let mut od_result: Vec<ProbeResult> = vec![];
    let mut od_time: Duration = Duration::from_millis(0);
    if opt.os_detection && ps_result.result_map.keys().len() > 0 {
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut od_targets: Vec<TargetInfo> = vec![];
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        od_targets.push(target);
        let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
        let pb = get_spinner();
        pb.set_message("Detecting os ...");
        let start_time: Instant = Instant::now();
        let handle = thread::spawn(move || {
            scan::run_os_fingerprinting(opt,  od_targets, &msg_tx)
        });
        while let Ok(_msg) = msg_rx.recv() {
            
        }
        pb.finish_and_clear();
        od_result = handle.join().unwrap();
        od_time = Instant::now().duration_since(start_time);
        println!("OS detection ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
    }

    if ps_result.result_map.keys().len() > 0 {
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let ports = ps_result.result_map.values().last().unwrap().clone();
        let tcp_map = db::get_tcp_map();
        let t_map: HashMap<u16, String> = HashMap::new();
        let service_map = sd_result.get(&ip).unwrap_or(&t_map);
        // PortInfo
        for port in ports {
            let port_info = result::PortInfo { 
                port_number: port.port.clone(), 
                port_status: format!("{:?}", port.status), 
                service_name: tcp_map.get(&port.port.to_string()).unwrap_or(&String::new()).to_string(), 
                service_version: service_map.get(&port.port).unwrap_or(&String::new()).to_string(), 
                remark: String::new(), 
            };     
            result.ports.push(port_info);  
        }
        // HostInfo
        let tcp_fingetprint =  if od_result.len() > 0 { os::verify_fingerprints(od_result[0].tcp_fingerprint.clone()) } else{ TCPFingerprint::new() };
        let host_info = result::HostInfo {
            ip_addr: ip.to_string(),
            host_name: dns_lookup::lookup_addr(&ip).unwrap_or(String::new()),
            mac_addr: String::new(),
            vendor_info: String::new(),
            os_name: tcp_fingetprint.os_name ,
            cpe: tcp_fingetprint.cpe,
        };
        result.host = host_info;
        result.port_scan_time = ps_result.scan_time;
        result.service_detection_time = sd_time;
        result.os_detection_time = od_time;
        result.total_scan_time = result.port_scan_time + result.service_detection_time + result.os_detection_time;
    }
    
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

}

pub fn handle_trace(opt: option::ScanOption) {
    
}

pub fn handle_domain_scan(opt: option::ScanOption) {
    
}

pub fn handle_uri_scan(opt: option::ScanOption) {
    
}
