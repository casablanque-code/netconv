use netconv_core::ir::NetworkConfig;
use netconv_core::report::ConversionReport;
use netconv_core::traits::ConfigParser;
use crate::tree::parse_raw_tree;
use crate::semantic::SemanticParser;

pub struct IosParser;

impl ConfigParser for IosParser {
    type Error = IosParseError;

    fn parse(&self, input: &str) -> Result<(NetworkConfig, ConversionReport), Self::Error> {
        let mut report = ConversionReport::new("Cisco IOS", "");

        // Pass 1: структурное дерево
        let tree = parse_raw_tree(input);

        // Pass 2: семантика → IR
        let semantic = SemanticParser;
        let config = semantic.analyze(&tree, &mut report);

        Ok((config, report))
    }

    fn vendor_name(&self) -> &str {
        "Cisco IOS"
    }
}

#[derive(Debug)]
pub enum IosParseError {
    Empty,
}

impl std::fmt::Display for IosParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IOS parse error: empty input")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
hostname CORE-RTR-01
ip domain-name corp.local
!
interface GigabitEthernet0/0
 description ** WAN Uplink **
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 no shutdown
!
interface GigabitEthernet0/1
 description ** LAN **
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
 ip helper-address 10.0.0.254
 no shutdown
!
interface Loopback0
 description Router-ID
 ip address 1.1.1.1 255.255.255.255
 no shutdown
!
router ospf 1
 router-id 1.1.1.1
 log-adjacency-changes
 network 10.0.0.0 0.0.0.255 area 0
 network 1.1.1.1 0.0.0.0 area 0
 passive-interface GigabitEthernet0/0
 default-information originate always
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
ip route 192.168.100.0 255.255.255.0 10.0.0.254 name BRANCH-1
!
ip access-list extended ACL-INTERNET-IN
 10 permit tcp any host 203.0.113.2 eq 443
 20 permit tcp any host 203.0.113.2 eq 80
 30 deny ip any any log
!
ip nat inside source list ACL-NAT interface GigabitEthernet0/0 overload
!
ntp server 216.239.35.0 prefer
ntp server 216.239.35.4
!
snmp-server community public RO
snmp-server location Moscow DC-1
"#;

    #[test]
    fn test_parse_hostname() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.hostname, Some("CORE-RTR-01".to_string()));
    }

    #[test]
    fn test_parse_interfaces() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.interfaces.len(), 3);

        let ge00 = cfg.interfaces.iter()
            .find(|i| i.name.original.contains("GigabitEthernet0/0"))
            .unwrap();
        assert!(!ge00.shutdown);
        assert_eq!(ge00.addresses.len(), 1);
        assert_eq!(ge00.addresses[0].prefix.to_string(), "203.0.113.2/30");
        assert_eq!(ge00.nat_direction, Some(netconv_core::ir::NatDirection::Outside));
    }

    #[test]
    fn test_parse_ospf() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.routing.ospf.len(), 1);

        let ospf = &cfg.routing.ospf[0];
        assert_eq!(ospf.process_id, 1);
        assert_eq!(ospf.router_id, Some("1.1.1.1".parse().unwrap()));
        assert!(ospf.log_adjacency);
        assert!(ospf.default_originate.is_some());
        assert!(ospf.default_originate.as_ref().unwrap().always);
        assert_eq!(ospf.passive_interfaces, vec!["GigabitEthernet0/0"]);
    }

    #[test]
    fn test_parse_static_routes() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.routing.static_routes.len(), 2);

        let default_route = cfg.routing.static_routes.iter()
            .find(|r| r.prefix.to_string() == "0.0.0.0/0")
            .unwrap();
        assert!(matches!(default_route.next_hop, netconv_core::ir::NextHop::Ip(_)));

        let branch = cfg.routing.static_routes.iter()
            .find(|r| r.name == Some("BRANCH-1".to_string()))
            .unwrap();
        assert_eq!(branch.prefix.to_string(), "192.168.100.0/24");
    }

    #[test]
    fn test_parse_acl() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.acls.len(), 1);

        let acl = &cfg.acls[0];
        assert!(matches!(&acl.name, netconv_core::ir::AclName::Named(n) if n == "ACL-INTERNET-IN"));
        assert_eq!(acl.entries.len(), 3);
        assert!(acl.entries[2].log);
    }

    #[test]
    fn test_parse_ntp() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(SAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.ntp.len(), 2);
        assert!(cfg.ntp[0].prefer);
    }

    // BGP tests
    const BGP_CONFIG: &str = r#"
hostname BGP-RTR-01
!
router bgp 65001
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes
 neighbor IBGP-PEERS peer-group
 neighbor IBGP-PEERS remote-as 65001
 neighbor IBGP-PEERS update-source Loopback0
 neighbor IBGP-PEERS next-hop-self
 neighbor 10.0.0.2 peer-group IBGP-PEERS
 neighbor 10.0.0.2 description RR-CLIENT-MSK
 neighbor 10.0.0.3 remote-as 65002
 neighbor 10.0.0.3 description EBGP-PEER
 neighbor 10.0.0.3 route-map RM-IN in
 neighbor 10.0.0.3 route-map RM-OUT out
 neighbor 10.0.0.3 send-community
 neighbor 10.0.0.3 remove-private-as
 !
 address-family ipv4
  network 192.168.0.0 mask 255.255.255.0
  network 10.0.0.0 mask 255.255.0.0
  redistribute connected
  aggregate-address 10.0.0.0 255.255.0.0 summary-only
  neighbor IBGP-PEERS activate
  neighbor 10.0.0.2 activate
  neighbor 10.0.0.3 activate
  neighbor 10.0.0.3 soft-reconfiguration inbound
  neighbor 10.0.0.3 default-originate
  exit-address-family
"#;

    #[test]
    fn test_bgp_basic() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(BGP_CONFIG).unwrap();
        let bgp = cfg.routing.bgp.as_ref().unwrap();
        assert_eq!(bgp.asn, 65001);
        assert_eq!(bgp.router_id, Some("1.1.1.1".parse().unwrap()));
        assert!(bgp.log_neighbor_changes);
    }

    #[test]
    fn test_bgp_peer_group() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(BGP_CONFIG).unwrap();
        let bgp = cfg.routing.bgp.as_ref().unwrap();
        assert_eq!(bgp.peer_groups.len(), 1);
        assert_eq!(bgp.peer_groups[0].name, "IBGP-PEERS");
    }

    #[test]
    fn test_bgp_neighbors() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(BGP_CONFIG).unwrap();
        let bgp = cfg.routing.bgp.as_ref().unwrap();

        let n02 = bgp.neighbors.iter()
            .find(|n| n.address == netconv_core::ir::BgpNeighborAddr::Ip("10.0.0.2".parse().unwrap()))
            .unwrap();
        assert_eq!(n02.peer_group, Some("IBGP-PEERS".to_string()));
        assert_eq!(n02.description, Some("RR-CLIENT-MSK".to_string()));

        let n03 = bgp.neighbors.iter()
            .find(|n| n.address == netconv_core::ir::BgpNeighborAddr::Ip("10.0.0.3".parse().unwrap()))
            .unwrap();
        assert_eq!(n03.remote_as, 65002);
        assert_eq!(n03.route_map_in, Some("RM-IN".to_string()));
        assert_eq!(n03.route_map_out, Some("RM-OUT".to_string()));
        assert!(n03.send_community);
        assert!(n03.remove_private_as);
    }

    #[test]
    fn test_bgp_address_family() {
        let parser = IosParser;
        let (cfg, _) = parser.parse(BGP_CONFIG).unwrap();
        let bgp = cfg.routing.bgp.as_ref().unwrap();

        assert_eq!(bgp.address_families.len(), 1);
        let af = &bgp.address_families[0];
        assert_eq!(af.afi, netconv_core::ir::BgpAfi::Ipv4);
        assert_eq!(af.safi, netconv_core::ir::BgpSafi::Unicast);
        assert_eq!(af.networks.len(), 2);
        assert!(af.networks.iter().any(|n| n.to_string() == "192.168.0.0/24"));
        assert!(af.networks.iter().any(|n| n.to_string() == "10.0.0.0/16"));
        assert_eq!(af.redistribute.len(), 1);
        assert!(matches!(af.redistribute[0].source, netconv_core::ir::RedistributeSource::Connected));
        assert_eq!(af.aggregate_addresses.len(), 1);
        assert!(af.aggregate_addresses[0].summary_only);
        assert_eq!(af.activated_neighbors.len(), 3);

        let n03_af = af.neighbor_settings.iter()
            .find(|n| n.address == netconv_core::ir::BgpNeighborAddr::Ip("10.0.0.3".parse().unwrap()))
            .unwrap();
        assert!(n03_af.soft_reconfiguration);
        assert!(n03_af.default_originate);
    }

    #[test]
    fn test_bgp_no_unknown_address_family() {
        let parser = IosParser;
        let (_, report) = parser.parse(BGP_CONFIG).unwrap();
        let af_unknowns: Vec<_> = report.items.iter()
            .filter(|i| i.severity == netconv_core::report::Severity::Info
                && i.source_snippet.contains("address-family"))
            .collect();
        assert!(af_unknowns.is_empty(),
            "address-family в unknown: {:?}", af_unknowns);
    }
}
