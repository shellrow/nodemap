use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use nodemap_core::result::{PingStat, TraceResult};
use nodemap_core::{option, scan, result, define};
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
    let result: result::PortScanResult = handle.join().unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

pub async fn handle_host_scan(opt: option::ScanOption) {
    let mut opt: option::ScanOption = opt;
    opt.oui_map = db::get_oui_map();
    opt.ttl_map = db::get_os_ttl();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_node_scan(opt, &msg_tx).await
        })
    });
    let mut pb = get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_HOSTSCAN => {pb.set_message("Scanning hosts ...");},
                define::MESSAGE_END_HOSTSCAN => {pb.finish_with_message("Host scan"); pb = get_spinner();},
                define::MESSAGE_START_ARPSCAN => {pb.set_message("ARP scan ...");},
                define::MESSAGE_END_ARPSCAN => {pb.finish_with_message("ARP scan"); pb = get_spinner();},
                _ => {},
            }
        }
    }
    pb.finish_and_clear();
    let result: result::HostScanResult = handle.join().unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

pub fn handle_ping(opt: option::ScanOption) {    
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let ping_opt = opt.clone();
    let handle = thread::spawn(move||{
        scan::run_ping(ping_opt, &msg_tx)
    });
    while let Ok(msg) = msg_rx.recv() {
        println!("{}", msg);
    }
    let result: PingStat = handle.join().unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

pub fn handle_trace(opt: option::ScanOption) {
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move||{
        scan::run_traceroute(opt, &msg_tx)
    });
    while let Ok(msg) = msg_rx.recv() {
        println!("{}", msg);
    }
    let result: TraceResult = handle.join().unwrap();
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")));
}

/* pub fn handle_domain_scan(opt: option::ScanOption) {
    
} */

/* pub fn handle_uri_scan(opt: option::ScanOption) {
    
} */
