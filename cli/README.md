# nodemap
Cross-platform network mapper

## Features
- Port Scan
- Host Scan
- Service detection (Experimental)
- OS detection (Experimental)
- Ping
- Traceroute
- Subdomain scan

## Installation
### Cargo Install
```
cargo install nodemap
```

## Basic Usage
```
USAGE:
    nodemap [OPTIONS]

OPTIONS:
    -p, --port <target>          Scan ports of the specified host.
                                 Use default port list if port range omitted.
                                 Examples:
                                 --port 192.168.1.8 -S -O
                                 --port 192.168.1.8:1-1000
                                 --port 192.168.1.8:22,80,8080
                                 --port 192.168.1.8 -l custom-list.txt
    -n, --host <target>          Scan hosts in specified network or host-list.
                                 Examples:
                                 --host 192.168.1.0
                                 --host custom-list.txt
                                 --host 192.168.1.10,192.168.1.20,192.168.1.30
    -g, --ping <target>          Ping to specified host. 
                                 Examples: 
                                 --ping 192.168.1.8 -c 4
    -e, --trace <target>         Traceroute to specified host. 
                                 Examples: 
                                 --trace 192.168.1.8
    -d, --domain <target>        Domain scan. 
                                 Examples: 
                                 --domain example.com
    -i, --interface <name>       Specify the network interface
    -s, --source <ip_addr>       Specify the source IP address
    -P, --protocol <protocol>    Specify the protocol
    -m, --maxhop <maxhop>        Set max hop(TTL) for ping or traceroute
    -T, --scantype <scantype>    Specify the scantype
    -t, --timeout <duration>     Set timeout in ms - Ex: -t 10000
    -w, --waittime <duration>    Set waittime in ms (default:100ms) - Ex: -w 200
    -r, --rate <duration>        Set sendrate in ms - Ex: -r 1
    -c, --count <count>          Set number of requests or pings to be sent
    -S, --service                Enable service detection
    -O, --os                     Enable OS detection
    -A, --async                  Perform asynchronous scan
    -l, --list <file_path>       Use list - Ex: -l custom-list.txt
    -C, --config <file_path>     Use config file
    -o, --save <file_path>       Save scan result in json format - Ex: -o result.json
        --acceptinvalidcerts     Accept invalid certs (This introduces significant vulnerabilities)
    -h, --help                   Print help information
    -V, --version                Print version information
```

## Supported platforms
- Linux
- macOS
- Windows
