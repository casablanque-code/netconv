//! Тесты на netconv_core::profile::detect_domain_mismatches.
//!
//! Цель: конфиг коммутатора (VLAN/trunk) не должен молча просачиваться
//! в L3-профиль и наоборот — до появления фильтрующих l2/l3 рендереров
//! это единственная защита от "бесполезной" межуровневой конвертации.

use netconv_core::profile::{detect_domain_mismatches, DeviceProfile};
use netconv_core::traits::ConfigParser;
use netconv_parser_ios::IosParser;

const SWITCH_CONFIG: &str = r#"
hostname ACCESS-SW-01
!
vlan 10
 name USERS
!
vlan 20
 name VOICE
!
interface GigabitEthernet0/1
 description user port
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet0/24
 description uplink
 switchport mode trunk
 switchport trunk allowed vlan 10,20
"#;

const ROUTER_CONFIG: &str = r#"
hostname EDGE-RTR-01
!
interface GigabitEthernet0/0
 description WAN
 ip address 203.0.113.2 255.255.255.252
!
router ospf 1
 network 203.0.113.0 0.0.0.3 area 0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
"#;

#[test]
fn switch_config_has_no_mismatches_under_l2_profile() {
    let (ir, _) = IosParser
        .parse(SWITCH_CONFIG)
        .expect("valid switch config should parse");
    let mismatches = detect_domain_mismatches(&ir, DeviceProfile::L2Switch);
    assert!(
        mismatches.is_empty(),
        "чистый L2-конфиг не должен давать несоответствий в L2-профиле: {:?}",
        mismatches
    );
}

#[test]
fn switch_config_is_flagged_under_l3_profile() {
    let (ir, _) = IosParser
        .parse(SWITCH_CONFIG)
        .expect("valid switch config should parse");
    let mismatches = detect_domain_mismatches(&ir, DeviceProfile::L3Router);
    assert!(
        !mismatches.is_empty(),
        "VLAN/trunk конфиг должен быть помечен как чужой домен в L3-профиле"
    );
    assert!(mismatches.iter().any(|m| m.domain == "L2/vlan"));
    assert!(mismatches.iter().any(|m| m.domain == "L2/switchport"));
}

#[test]
fn router_config_has_no_mismatches_under_l3_profile() {
    let (ir, _) = IosParser
        .parse(ROUTER_CONFIG)
        .expect("valid router config should parse");
    let mismatches = detect_domain_mismatches(&ir, DeviceProfile::L3Router);
    assert!(
        mismatches.is_empty(),
        "чистый L3-конфиг не должен давать несоответствий в L3-профиле: {:?}",
        mismatches
    );
}

#[test]
fn router_config_is_flagged_under_l2_profile() {
    let (ir, _) = IosParser
        .parse(ROUTER_CONFIG)
        .expect("valid router config should parse");
    let mismatches = detect_domain_mismatches(&ir, DeviceProfile::L2Switch);
    assert!(
        !mismatches.is_empty(),
        "OSPF/static конфиг должен быть помечен как чужой домен в L2-профиле"
    );
    assert!(mismatches.iter().any(|m| m.domain == "L3/ospf"));
    assert!(mismatches.iter().any(|m| m.domain == "L3/static"));
}
