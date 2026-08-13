//! Network guard primitives shared by every egress path (typed connectors,
//! the transparent egress proxy): the address ranges a guest-originated
//! connection must never reach.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The cloud metadata endpoints, refused explicitly (defense in depth: both
/// already fall in ranges [`is_forbidden_ip`] refuses).
pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);

/// Is this address in a range that must never be reached from a guest?
/// Loopback, RFC1918 private, link-local (incl. 169.254.169.254 metadata),
/// CGNAT, unique-local, v6 link-local, unspecified, broadcast, and the cloud
/// metadata addresses.
pub fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // includes 169.254.169.254 metadata
                || v4.is_unspecified()
                || v4.is_broadcast()
                || *v4 == METADATA_V4
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique local fc00::/7 (includes fd00:ec2::254 metadata)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || *v6 == METADATA_V6
                // v4-mapped: recurse
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_forbidden_ip(&IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_ranges_are_refused() {
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.7",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fd00:ec2::254",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_forbidden_ip(&ip(bad)), "{bad} must be forbidden");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for good in [
            "93.184.216.34",
            "8.8.8.8",
            "2606:2800:220:1::1",
            "100.63.0.1",
            "100.128.0.1",
        ] {
            assert!(!is_forbidden_ip(&ip(good)), "{good} must be allowed");
        }
    }
}
