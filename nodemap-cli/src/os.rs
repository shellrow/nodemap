use std::collections::HashMap;
use netscan::os::TcpFingerprint;
use super::db;
use super::model::TCPFingerprint;

pub fn verify_fingerprints(fingerprint: TcpFingerprint) -> TCPFingerprint {
    let fingerprints:Vec<TCPFingerprint> = db::get_tcp_fingerprints();
    let mut map: HashMap<String, (u32, TCPFingerprint)> = HashMap::new();
    for f in fingerprints {
        let mut point: u32 = 0;
        let mut index: usize = 0;
        // Exact match
        if index < fingerprint.tcp_syn_ack_fingerprint.len() {
            for sf in f.syn_fingerprints.clone() {
                if sf.tcp_window_size == fingerprint.tcp_syn_ack_fingerprint[index].tcp_window_size {
                    point += 1;
                }
                let mut opsions : Vec<String> = vec![];
                for option in &fingerprint.tcp_syn_ack_fingerprint[index].tcp_option_order {
                    opsions.push(option.name());
                }
                //let options = fingerprint.tcp_syn_ack_fingerprint[index].tcp_option_o
                if sf.tcp_options == opsions {
                    point += 4;
                }
            }
        }
        if f.ecn_fingerprint.tcp_ecn_support == fingerprint.tcp_enc_fingerprint.tcp_ecn_support {
            point += 1;
        }
        if f.ecn_fingerprint.ip_df == fingerprint.tcp_enc_fingerprint.ip_df {
            point += 1;
        }
        if f.ecn_fingerprint.tcp_window_size == fingerprint.tcp_enc_fingerprint.tcp_window_size {
            point += 1;
        }
        let mut opsions : Vec<String> = vec![];
        for option in &fingerprint.tcp_syn_ack_fingerprint[index].tcp_option_order {
            opsions.push(option.name());
        }
        if f.ecn_fingerprint.tcp_options == opsions {
            point += 4;
        }
        if point >= 20 {
            map.insert(f.clone().cpe, (point, f));
        }
        index += 1;
    }
    match map.iter().max_by(|a, b| a.1.0.cmp(&b.1.0)).map(|(k, _v)| k){
        Some(cpe) => {
            let kv = map.get(cpe).unwrap();
            println!("{} {}", kv.0, kv.1.cpe);
            return map.get(cpe).unwrap().1.clone();
        },   
        None => {
            return TCPFingerprint::new()
        },
    }
}
