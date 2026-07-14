//! Вторая пара из roadmap, разделённая на профили: ios -> eltex.
//! EltexL2Renderer целится в MES (switch), EltexL3Renderer — в ESR
//! (router/firewall), как и раньше под именем EltexRenderer.

use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_eltex::{EltexL2Renderer, EltexL3Renderer, EltexRenderer};

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
 spanning-tree portfast
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
interface GigabitEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
!
router ospf 1
 network 203.0.113.0 0.0.0.3 area 0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
"#;

#[test]
fn l2_renderer_emits_vlan_database_and_switchport_only() {
    let output = convert(&IosParser, &EltexL2Renderer, SWITCH_CONFIG)
        .expect("switch config should convert under EltexL2Renderer");
    let cfg = &output.config_text;

    assert!(cfg.contains("vlan database"), "должна быть VLAN database");
    assert!(
        cfg.contains("vlan 10 name USERS"),
        "VLAN 10 с именем должен присутствовать"
    );
    assert!(
        cfg.contains("switchport mode access"),
        "access-порт должен быть отрендерен"
    );
    assert!(
        cfg.contains("switchport mode trunk"),
        "trunk-порт должен быть отрендерен"
    );
    assert!(
        cfg.contains("spanning-tree portfast"),
        "portfast переносится дословно"
    );

    assert!(
        !cfg.contains("security zone"),
        "L2-вывод не должен содержать security zones (ESR-специфика)"
    );
    assert!(
        !cfg.contains("router ospf") && !cfg.contains(" ospf "),
        "L2-вывод не должен содержать routing"
    );
}

#[test]
fn l3_renderer_emits_addressing_routing_zones_only() {
    let output = convert(&IosParser, &EltexL3Renderer, ROUTER_CONFIG)
        .expect("router config should convert under EltexL3Renderer");
    let cfg = &output.config_text;

    assert!(
        cfg.contains("ip address 203.0.113.2"),
        "адресация должна быть отрендерена"
    );
    assert!(
        cfg.contains("security zone") || cfg.contains("zone "),
        "ESR-профиль должен содержать security zones"
    );

    assert!(
        !cfg.contains("vlan database"),
        "L3-вывод не должен содержать VLAN database"
    );
    assert!(
        !cfg.contains("switchport"),
        "L3-вывод не должен содержать switchport"
    );
}

#[test]
fn l2_renderer_drops_l3_content_present_in_mixed_source() {
    let output = convert(&IosParser, &EltexL2Renderer, ROUTER_CONFIG)
        .expect("router-only source should still render under L2 profile");
    let cfg = &output.config_text;

    assert!(
        !cfg.contains("security zone"),
        "L2-профиль обязан игнорировать security zones"
    );
    assert!(
        !cfg.contains("router ospf"),
        "L2-профиль обязан игнорировать routing"
    );
}

#[test]
fn legacy_eltex_renderer_still_targets_esr() {
    // Обратная совместимость: старое имя EltexRenderer должно вести себя
    // так же, как EltexL3Renderer — ни один существующий вызов не ломается.
    let output = convert(&IosParser, &EltexRenderer, ROUTER_CONFIG)
        .expect("legacy EltexRenderer should still handle router config");
    assert!(output.config_text.contains("ip address 203.0.113.2"));
    assert_eq!(output.report.target_vendor, "Eltex ESR");
}
