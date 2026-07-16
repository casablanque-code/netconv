//! Regression-тест на реальный баг, найденный в проде: report item для
//! interface.description (и других 1:1 полей интерфейса) показывал в
//! "было" строку "interface GigabitEthernet0/1" вместо настоящей
//! исходной команды ("description ..."), из-за чего "было"/"стало" не
//! соответствовали действительности — при том что severity была
//! "Точное соответствие". Причина: во всех этих местах в source_snippet
//! передавался `src_block`/`ctx` (текстовая метка "какой это интерфейс"),
//! а не текст самой команды.
//!
//! Тест фиксирует инвариант: source_snippet для этих категорий обязан
//! содержать реальный текст исходной команды, а не только имя интерфейса.

use netconv_core::report::ReportItem;
use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_eltex::{EltexL2Renderer, EltexRenderer};
use netconv_render_vrp::VrpRenderer;

const CONFIG: &str = r#"
hostname ROUTER-01
!
interface GigabitEthernet0/1
 description ** LAN - Office **
 mtu 9000
 duplex full
 no shutdown
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
"#;

fn find_source_snippet<'a>(items: &'a [ReportItem], category: &str) -> Option<&'a str> {
    items.iter().find(|i| i.category == category).map(|i| i.source_snippet.as_str())
}

#[test]
fn vrp_description_snippet_contains_actual_text_not_just_interface_name() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG).expect("should convert");
    let snippet = find_source_snippet(&output.report.items, "interface.description")
        .expect("interface.description item should exist");

    assert!(
        snippet.contains("LAN - Office"),
        "source_snippet должен содержать реальный текст description, получено: {}",
        snippet
    );
    assert!(
        snippet.starts_with("description"),
        "source_snippet должен начинаться с реальной Cisco-команды, а не с 'interface ...', получено: {}",
        snippet
    );
}

#[test]
fn vrp_mtu_and_duplex_snippets_are_not_bare_interface_names() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG).expect("should convert");

    let mtu = find_source_snippet(&output.report.items, "interface.mtu").expect("mtu item");
    assert!(mtu.contains("mtu 9000"), "получено: {}", mtu);
    assert!(
        !mtu.trim_start().starts_with("interface "),
        "не должно быть голым 'interface X', получено: {}",
        mtu
    );

    let duplex = find_source_snippet(&output.report.items, "interface.duplex").expect("duplex item");
    assert!(duplex.contains("duplex full"), "получено: {}", duplex);
}

#[test]
fn vrp_l2_snippet_shows_switchport_command_not_interface_name() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG).expect("should convert");
    let snippet = find_source_snippet(&output.report.items, "interface.l2").expect("interface.l2 item");
    assert!(
        snippet.contains("switchport mode access"),
        "должна быть видна реальная switchport-команда, получено: {}",
        snippet
    );
}

#[test]
fn eltex_l2_stp_portfast_snippet_is_the_real_command() {
    let output = convert(&IosParser, &EltexL2Renderer, CONFIG).expect("should convert");
    let snippet = find_source_snippet(&output.report.items, "stp.portfast").expect("stp.portfast item");
    assert!(snippet.contains("spanning-tree portfast"), "получено: {}", snippet);
}

#[test]
fn eltex_esr_description_snippet_contains_actual_text() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG).expect("should convert");
    let snippet = find_source_snippet(&output.report.items, "interface.description").expect("description item");
    assert!(snippet.contains("LAN - Office"), "получено: {}", snippet);
}
