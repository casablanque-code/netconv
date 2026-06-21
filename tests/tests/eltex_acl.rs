//! Сквозной тест на баг #3 из ревью: Eltex рендерил "ip access-group NAME in"
//! на интерфейсе, но само тело ACL ("ip access-list ... permit/deny ...")
//! нигде не выводилось — итоговый конфиг ссылался на несуществующий ACL.

use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_eltex::EltexRenderer;

const CONFIG_WITH_ACL: &str = r#"
hostname EDGE-RTR
!
interface GigabitEthernet0/0
 description WAN
 ip address 203.0.113.2 255.255.255.252
 ip access-group ACL-INTERNET-IN in
 no shutdown
!
ip access-list extended ACL-INTERNET-IN
 10 permit tcp any host 203.0.113.2 eq 443
 20 permit tcp any host 203.0.113.2 eq 80
 30 deny ip any any log
"#;

#[test]
fn eltex_renders_acl_body_referenced_by_interface() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_ACL).expect("conversion should succeed");

    // Ссылка на интерфейсе должна быть на месте (это уже работало раньше).
    assert!(
        output.config_text.contains("ip access-group ACL-INTERNET-IN in"),
        "interface should still reference the ACL:\n{}",
        output.config_text
    );

    // Само тело ACL обязано присутствовать — раньше отсутствовало полностью.
    assert!(
        output.config_text.contains("ip access-list") && output.config_text.contains("ACL-INTERNET-IN"),
        "ACL body (ip access-list ACL-INTERNET-IN ...) must be rendered, config was:\n{}",
        output.config_text
    );

    // Конкретные правила должны попасть в вывод.
    assert!(output.config_text.contains("443"), "rule matching port 443 should be present");
    assert!(output.config_text.contains("80"), "rule matching port 80 should be present");
    assert!(
        output.config_text.to_lowercase().contains("deny"),
        "deny rule should be present"
    );
}

#[test]
fn eltex_acl_entries_appear_in_report() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_ACL).expect("conversion should succeed");
    let acl_items = output.report.items.iter()
        .filter(|i| i.category == "acl.entry")
        .count();
    // 3 правила в исходном ACL → минимум 3 записи в отчёте.
    assert!(acl_items >= 3, "expected at least 3 acl.entry report items, got {}", acl_items);
}
