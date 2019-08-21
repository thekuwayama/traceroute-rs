# traceroute-rs

[![Build Status](https://travis-ci.org/thekuwayama/traceroute-rs.svg?branch=master)](https://travis-ci.org/thekuwayama/traceroute-rs)
[![MIT licensed](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://raw.githubusercontent.com/thekuwayama/traceroute-rs/master/LICENSE.txt)

`traceroute-rs` is `traceroute` implemented by Rust.

`traceroute-rs` sends ICMP Echo Request packets with TTL values that gradually increase from packet to packet, starting with a TTL value of one. 

## Usage

You can build and run `traceroute-rs` with the following:

```bash
$ git clone git@github.com:thekuwayama/traceroute-rs.git

$ cd traceroute-rs

$ cargo build

$ sudo ./target/debug/traceroute-rs 1.1.1.1
```

## License

The CLI is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
