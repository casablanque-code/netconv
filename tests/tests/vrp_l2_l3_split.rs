//! Первая "безупречная" пара из roadmap: ios -> vrp с разделением на
//! L2 (VrpL2Renderer) и L3 (VrpL3Renderer). Тесты проверяют не только
//! что нужный домен присутствует, но и что чужой домен НЕ просочился
//! в вывод — это и есть весь смысл разделения.

use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_vrp::{VrpL2Renderer, VrpL3Renderer, VrpRenderer};

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
ip access-list extended BLOCK-TELNET
 deny tcp any any eq 23
 permit ip any any
!
ip route 0.0.0.0 0.0.0.0 203.0.113.1
"#;

#[test]
fn l2_renderer_emits_vlan_and_switchport_only() {
    let output = convert(&IosParser, &VrpL2Renderer, SWITCH_CONFIG)
        .expect("switch config should convert under VrpL2Renderer");
    let cfg = &output.config_text;

    assert!(cfg.contains("vlan 10"), "VLAN 10 должен присутствовать в L2-выводе");
    assert!(cfg.contains("port link-type access"), "access-порт должен быть отрендерен");
    assert!(cfg.contains("port link-type trunk"), "trunk-порт должен быть отрендерен");
    assert!(cfg.contains("stp edged-port enable"), "portfast -> stp edged-port enable");

    // Чужой домен не должен просочиться — в исходнике его и нет, но это
    // всё равно фиксирует границу поведения рендерера явно.
    assert!(!cfg.contains("ospf"), "L2-вывод не должен содержать routing");
    assert!(!cfg.contains("traffic-filter"), "L2-вывод не должен содержать ACL");
}

#[test]
fn l3_renderer_emits_routing_acl_addressing_only() {
    let output = convert(&IosParser, &VrpL3Renderer, ROUTER_CONFIG)
        .expect("router config should convert under VrpL3Renderer");
    let cfg = &output.config_text;

    assert!(cfg.contains("ip address 203.0.113.2"), "адресация должна быть отрендерена");
    assert!(cfg.contains("ospf"), "OSPF должен быть отрендерен");
    assert!(cfg.contains("acl"), "ACL должен быть отрендерен");
    assert!(cfg.contains("ip route-static"), "статический маршрут должен быть отрендерен");

    // Чужой домен (VLAN/switchport) не должен просочиться
    assert!(!cfg.contains("vlan "), "L3-вывод не должен содержать VLAN database");
    assert!(!cfg.contains("port link-type"), "L3-вывод не должен содержать switchport");
}

#[test]
fn l3_renderer_drops_l2_content_present_in_source() {
    // Смешанный вход (в реальности так быть не должно, но парсер его
    // всё равно разберёт) — L3-рендерер обязан отфильтровать L2-часть.
    let output = convert(&IosParser, &VrpL3Renderer, SWITCH_CONFIG)
        .expect("mixed-domain source should still render under L3 profile");
    let cfg = &output.config_text;

    assert!(!cfg.contains("port link-type"), "L3-профиль обязан игнорировать switchport из входа");
    assert!(!cfg.contains("vlan 10\n"), "L3-профиль обязан игнорировать VLAN database из входа");
}

#[test]
fn legacy_vrp_renderer_still_renders_everything() {
    // Обратная совместимость: старый VrpRenderer (используется без
    // --profile) не должен менять поведение — иначе ломаем всё, что
    // уже полагается на convert(&IosParser, &VrpRenderer, ..).
    let output = convert(&IosParser, &VrpRenderer, SWITCH_CONFIG)
        .expect("legacy VrpRenderer should still handle switch config");
    assert!(output.config_text.contains("vlan 10"));
    assert!(output.config_text.contains("port link-type access"));
}
