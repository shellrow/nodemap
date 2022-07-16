use std::hash::Hash;
use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use std::collections::HashMap;
use std::net::IpAddr;
use netscan::os::ProbeResult;
use netscan::result::{PortScanResult as NsPortScanResult, HostScanResult, ScanStatus};
use nodemap_core::option::TargetInfo;
use nodemap_core::{option, scan, result};
use console::{Term, Style, Emoji};
use indicatif::{ProgressBar, ProgressStyle, ProgressFinish};
use super::os;

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
        //scan::run_port_scan(opt, &msg_tx)
    });

    let pb = get_spinner();
    pb.set_message("Scanning ports ...");
    // Print progress
    //term.set_title("Progress...");
    while let Ok(_msg) = msg_rx.recv() {
        //term.write_line(&format!("from Scanner: {}", msg)).unwrap();
        //term.move_cursor_up(1).unwrap();
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
            println!("Port scan ... {} {}", Emoji::new("❌", ""),Style::new().green().apply_to("Done"));
        },
    }

    // Service Detection
    let mut sd_result: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    if ps_result.result_map.keys().len() > 0 {
        let mut sd_targets: Vec<TargetInfo> = vec![];
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        sd_targets.push(target);
        let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
        let pb = get_spinner();
        pb.set_message("Detecting services ...");
        let handle = thread::spawn(move || {
            scan::run_service_detection(sd_targets, &msg_tx)
        });
        while let Ok(_msg) = msg_rx.recv() {
            
        }
        pb.finish_and_clear();
        sd_result = handle.join().unwrap();
        println!("Service detection ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
    }

    // OS Detection
    let mut od_result: Vec<ProbeResult> = vec![];
    if ps_result.result_map.keys().len() > 0 {
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut od_targets: Vec<TargetInfo> = vec![];
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        od_targets.push(target);
        let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
        let pb = get_spinner();
        pb.set_message("Detecting os ...");
        let handle = thread::spawn(move || {
            scan::run_os_fingerprinting(opt,  od_targets, &msg_tx)
        });
        while let Ok(_msg) = msg_rx.recv() {
            
        }
        pb.finish_and_clear();
        od_result = handle.join().unwrap();
        println!("OS detection ... {} {}",Emoji::new("✅", ""),Style::new().green().apply_to("Done"));
    }

    // Print results 
    println!("Results:");
    for (ip, ports) in ps_result.result_map {
        println!("{}", ip);
        for port in ports {
            println!("{:?}", port);
        }
    }
    println!("Scan Time: {:?}", ps_result.scan_time);

    for r in sd_result {
        println!("{} {:?}", r.0, r.1);
    }

    for r in od_result {
        let f = os::verify_fingerprints(r.tcp_fingerprint);
        println!("{} {:?}", r.ip_addr, f);
    }

}

pub fn handle_host_scan(opt: option::ScanOption) {

}

pub fn handle_ping(opt: option::ScanOption) {

}

pub fn handle_trace(opt: option::ScanOption) {
    
}

pub fn handle_domain_scan(opt: option::ScanOption) {
    
}

pub fn handle_uri_scan(opt: option::ScanOption) {
    
}
