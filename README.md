# cidr-block-parser

Parses and validates IPv4/IPv6 CIDR notation, providing network address, broadcast, and range calculations.

```rust
use cidr_block_parser::CidrBlock;
use std::net::IpAddr;

let block = CidrBlock::parse("192.168.1.0/24").unwrap();
assert_eq!(block.network(), "192.168.1.0".parse::<IpAddr>().unwrap());
assert_eq!(block.broadcast(), "192.168.1.255".parse::<IpAddr>().unwrap());
assert_eq!(block.first_host(), "192.168.1.1".parse::<IpAddr>().unwrap());
assert_eq!(block.last_host(), "192.168.1.254".parse::<IpAddr>().unwrap());
assert!(block.contains("192.168.1.42".parse::<IpAddr>().unwrap()));
```

## Why this exists

Most CIDR parsers silently mask host bits, turning `192.168.1.5/24` into `192.168.1.0/24`. That hides a common configuration mistake: an address was intended to be a network address but was not. This library rejects such input with `CidrError::HostBitsSet`. The trade-off is that callers who genuinely want normalisation must do it themselves, but callers who want to catch typos get a clear error instead of a silently changed value.

## Edge cases

The IPv4 `/31` and `/32` prefixes have no distinct host range. For those, `first_host` and `last_host` return the network and broadcast addresses respectively, which are the only addresses in the block. IPv6 has no broadcast address in the traditional sense; `broadcast` returns the highest address in the block, and `first_host`/`last_host` return the addresses immediately inside the block boundaries.
