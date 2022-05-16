# synscan-go SYN Port scanner written in Go

`synscan-go` is a simple SYN port scanner written in Pure Go. with no libpcap required.

Only support linux system.

# Features
* Blazing fast scan speed. only 5s for /24 ip range.
* Written in pure Go. no c libs required.

## Installation

```bash
go install github.com/sleshep/synscan-go@latest
```

## Usage

```bash
Usage of ./synscan-go:
  ./synscan-go [options]

Examples:
  ./synscan-go -t 10.0.0.0/24,192.168.1.0/24 -p 80,443,8080-8090 -o result.txt

  -a    attack mode, keep sending to target, default is false
  -c int
        source port, default 50001 (default 50001)
  -o string
        result output file, default is stdout (default "-")
  -p string
        port or port range, e.g. 80,443,8080-8090, default 80,443 (default "80,443")
  -r int
        rate limit, in packets per second, default is 100k packets per second (default 100000)
  -s    silence, no info output, default is false
  -t string
        Target IP address, comma separated list of IP or CIDR notation, e.g. 192.168.1.0/24,10.0.0.0/24, default is 192.168.0.0/24 (default "192.168.0.0/24")
  -w duration
        wait for finish (default 1s)
```

## License

See [LICENSE](LICENSE) for more information.
