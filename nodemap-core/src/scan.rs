use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::fs::{read, read_to_string};
use std::collections::HashMap;
use netscan::result::{PortScanResult, HostScanResult};
use netscan::setting::Destination;
use netscan::blocking::{PortScanner, HostScanner};
use netscan::async_io::{PortScanner as AsyncPortScanner, HostScanner as AsyncHostScanner};
use netscan::os::{Fingerprinter, ProbeTarget, ProbeType, ProbeResult};
use netscan::service::{ServiceDetector, PortDatabase};
use webscan::RequestMethod;
use webscan::{UriScanner, DomainScanner};
use webscan::{UriScanResult, DomainScanResult};
use tracert::trace::{Tracer, TraceResult};
use tracert::ping::{Pinger, PingResult};

use crate::option::TargetInfo;

use super::option::ScanOption;

pub fn run_port_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> PortScanResult {
    let mut port_scanner = match PortScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: Destination = Destination::new(opt.targets[0].ip_addr, opt.targets[0].ports.clone());
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(opt.port_scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        port_scanner.scan()
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_port_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> PortScanResult {
    let mut port_scanner = match AsyncPortScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: Destination = Destination::new(opt.targets[0].ip_addr, opt.targets[0].ports.clone());
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(opt.port_scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            port_scanner.scan().await
        })
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_host_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> HostScanResult {
    let mut host_scanner = match HostScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: Destination = Destination::new(target.ip_addr, target.ports);
        host_scanner.add_destination(dst);
    }
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        host_scanner.scan()
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_host_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> HostScanResult {
    let mut host_scanner = match AsyncHostScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: Destination = Destination::new(target.ip_addr, target.ports);
        host_scanner.add_destination(dst);
    }
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            host_scanner.scan().await
        })
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_service_detection(targets: Vec<TargetInfo>, msg_tx: mpsc::Sender<String>) -> HashMap<IpAddr, HashMap<u16, String>> {
    let mut map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    for target in targets {
        let mut service_detector = ServiceDetector::new();
        service_detector.set_dst_ip(target.ip_addr);
        service_detector.set_open_ports(target.ports);
        let service_map: HashMap<u16, String> = service_detector.detect(Some(PortDatabase::default()));
        map.insert(target.ip_addr, service_map);
        match msg_tx.send(target.ip_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    map
}

pub fn run_os_fingerprinting(opt: ScanOption, targets: Vec<TargetInfo>, _msg_tx: mpsc::Sender<String>) -> Vec<ProbeResult> {
    let mut fingerprinter = Fingerprinter::new(opt.src_ip).unwrap();
    fingerprinter.set_wait_time(opt.wait_time);
    for target in targets {
        let probe_target: ProbeTarget = ProbeTarget {
            ip_addr: target.ip_addr,
            open_tcp_ports: target.ports,
            closed_tcp_port: 0,
            open_udp_port: 0,
            closed_udp_port: 33455,
        };
        fingerprinter.add_probe_target(probe_target);
    }
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpProbe);
    let results = fingerprinter.probe();
    results
}

pub fn run_ping(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> PingResult {
    let pinger: Pinger = Pinger::new(opt.targets[0].ip_addr).unwrap();
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move|| {
        pinger.ping()
    });
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!("{} {} {:?} {:?}", node.seq, node.ip_addr, node.hop, node.rtt)) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap().unwrap();
    result
}

pub fn run_traceroute(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> TraceResult {
    let tracer: Tracer = Tracer::new(opt.targets[0].ip_addr).unwrap();
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move|| {
        tracer.trace()
    });
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!("{} {} {:?} {:?}", node.seq, node.ip_addr, node.hop, node.rtt)) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap().unwrap();
    result
}

pub async fn run_uri_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> UriScanResult {
    let mut uri_scanner = match UriScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    uri_scanner.set_base_uri(opt.targets[0].base_uri.clone());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path);
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for word in word_list {
            uri_scanner.add_word(word.to_string());
        }
    }
    if opt.use_content {
        match read(opt.content_path.to_string()) {
            Ok(ct) => {
                let sep = b'\n';
                ct.split(|b| b == &sep )
                    .for_each(|c| uri_scanner.add_content(c.to_vec()));
            },
            Err(e) => {panic!("Could not open or find content file {} due to {}", opt.content_path.to_string(), e);}
        }
    }
    if !opt.request_method.is_empty() {
        if opt.request_method.to_uppercase() == "POST" {
            uri_scanner.set_request_method(RequestMethod::Post);
        }else{
            uri_scanner.set_request_method(RequestMethod::Get);
        }
    }
    uri_scanner.set_timeout(opt.timeout);
    let rx = uri_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            uri_scanner.scan().await
        })
    });
    while let Ok(uri) = rx.lock().unwrap().recv() {
        match msg_tx.send(uri) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_domain_scan(opt: ScanOption, msg_tx: mpsc::Sender<String>) -> DomainScanResult {
    let mut domain_scanner = match DomainScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(opt.targets[0].base_domain.clone());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path.to_string());
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for d in word_list{
            domain_scanner.add_word(d.to_string());
        }
    }
    domain_scanner.set_timeout(opt.timeout);
    let rx = domain_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            domain_scanner.scan().await
        })
    });
    while let Ok(domain) = rx.lock().unwrap().recv() {
        match msg_tx.send(domain) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}
