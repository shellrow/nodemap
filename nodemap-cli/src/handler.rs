use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use netscan::result::{PortScanResult, HostScanResult};
use nodemap_core::{option, scan};
use console::Term;

pub fn handle_port_scan(opt: option::ScanOption) {
    let term = Term::stdout();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    // Run scan 
    let handle = thread::spawn(move|| {
        scan::run_port_scan(opt, &msg_tx)
    });
    // Print progress
    term.set_title("Progress...");
    while let Ok(msg) = msg_rx.recv() {
        term.write_line(&format!("from Scanner: {}", msg)).unwrap();
        term.move_cursor_up(1).unwrap();
    }
    let result: PortScanResult = handle.join().unwrap();
    // Print results 
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for (ip, ports) in result.result_map {
        println!("{}", ip);
        for port in ports {
            println!("{:?}", port);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
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
