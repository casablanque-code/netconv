//! Сквозные тесты: ip nat pool / ip nat inside source list ... pool ... overload
//!
//! Регрессия (баг #2 из ревью): "ip nat pool NAME start end ..." не парсился
//! вообще, а ссылка на пул создавала NatPool{start: 0.0.0.0, end: 0.0.0.0},
//! которая утекала в финальный VRP/Eltex конфиг как рабочий NAT — без единого
//! предупреждения в отчёте, хотя реальные границы пула были потеряны.

use netconv_core::traits::{convert, ConfigParser};
use netconv_parser_ios::IosParser;
use netconv_render_eltex::EltexRenderer;
use netconv_render_vrp::VrpRenderer;

const CONFIG_WITH_NAT_POOL: &str = r#"
hostname EDGE-RTR
!
interface GigabitEthernet0/0
 description WAN
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 no shutdown
!
interface GigabitEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
 no shutdown
!
ip nat pool OFFICE-POOL 192.168.1.10 192.168.1.20 prefix-length 24
ip nat inside source list NAT-ACL pool OFFICE-POOL
!
ip access-list standard NAT-ACL
 10 permit 10.0.0.0 0.0.0.255
"#;

#[test]
fn vrp_nat_pool_uses_real_addresses_not_zero() {
    let output =
        convert(&IosParser, &VrpRenderer, CONFIG_WITH_NAT_POOL).expect("conversion should succeed");
    assert!(
        !output.config_text.contains("0.0.0.0 0.0.0.0"),
        "VRP output must not contain a zeroed NAT pool:\n{}",
        output.config_text
    );
    assert!(
        output.config_text.contains("192.168.1.10") && output.config_text.contains("192.168.1.20"),
        "VRP output must contain the real pool boundaries:\n{}",
        output.config_text
    );
}

#[test]
fn eltex_nat_pool_uses_real_addresses_not_zero() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_NAT_POOL)
        .expect("conversion should succeed");
    // ESR dynamic (non-overload) NAT с пулом сейчас осознанно помечается Manual
    // (нет полной поддержки в Eltex рендерере), но если когда-нибудь это
    // изменится, всё равно нельзя допустить тихую подстановку 0.0.0.0.
    assert!(
        !output.config_text.contains("0.0.0.0 0.0.0.0"),
        "Eltex output must not contain a zeroed NAT pool:\n{}",
        output.config_text
    );
}

const CONFIG_WITH_NAT_POOL_OVERLOAD: &str = r#"
hostname EDGE-RTR
!
interface GigabitEthernet0/0
 description WAN
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 no shutdown
!
interface GigabitEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
 no shutdown
!
ip nat pool OFFICE-POOL 192.168.1.10 192.168.1.20 prefix-length 24
ip nat inside source list NAT-ACL pool OFFICE-POOL overload
!
ip access-list standard NAT-ACL
 10 permit 10.0.0.0 0.0.0.255
"#;

#[test]
fn vrp_nat_pool_overload_uses_real_addresses() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG_WITH_NAT_POOL_OVERLOAD)
        .expect("conversion should succeed");
    assert!(
        !output.config_text.contains("0.0.0.0 0.0.0.0"),
        "VRP NAT overload+pool output must not be zeroed:\n{}",
        output.config_text
    );
    assert!(output.config_text.contains("192.168.1.10"));
    assert!(output.config_text.contains("192.168.1.20"));
}

const CONFIG_WITH_UNDEFINED_POOL: &str = r#"
hostname EDGE-RTR
!
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
 no shutdown
!
ip nat inside source list NAT-ACL pool GHOST-POOL overload
!
ip access-list standard NAT-ACL
 10 permit 10.0.0.0 0.0.0.255
"#;

#[test]
fn parser_marks_undefined_pool_reference_as_manual() {
    // Если в конфиге есть ссылка на пул, но самого "ip nat pool NAME ..."
    // нет (например, он находится в другом, не загруженном файле/секции),
    // отчёт обязан явно пометить это как Manual, а не молча сгенерировать
    // 0.0.0.0 как будто всё в порядке.
    let parser = IosParser;
    let (cfg, report) = parser
        .parse(CONFIG_WITH_UNDEFINED_POOL)
        .expect("parse should succeed");

    assert_eq!(cfg.nat.len(), 1);
    let manual_count = report
        .items
        .iter()
        .filter(|i| i.category == "nat.pool_undefined")
        .count();
    assert_eq!(
        manual_count, 1,
        "undefined pool reference must produce exactly one manual report item"
    );
}
