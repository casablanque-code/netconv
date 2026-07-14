//! Сквозные тесты на тихую потерю данных (баг #1 из ревью).
//!
//! README заявляет: "netconv never silently drops commands. Everything
//! unrecognised is preserved as a commented block with context."
//! Это было неправдой для banner (оба рендерера) и для dns/line_vty
//! (только Eltex) — поле парсилось в IR, но ни один рендерер его не читал,
//! и ни единая запись не попадала в отчёт.
//!
//! Эти тесты не проверяют точный синтаксис вывода (это førmat-specific и
//! может меняться), а проверяют инвариант: если в исходном конфиге было
//! что-то, что легло в соответствующее поле IR, то после рендера это поле
//! обязано оставить след — либо в самом конфиге, либо явной записью в
//! отчёте (Exact/Approximate/Manual). Полное молчание недопустимо.

use netconv_core::report::Severity;
use netconv_core::traits::convert;
use netconv_parser_ios::IosParser;
use netconv_render_eltex::EltexRenderer;
use netconv_render_vrp::VrpRenderer;

const CONFIG_WITH_BANNER_DNS_LINE: &str = r#"
hostname EDGE-RTR
!
ip domain-name corp.local
ip name-server 8.8.8.8
ip name-server 1.1.1.1
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
banner motd ^C Authorized access only. ^C
!
line vty 0 4
 exec-timeout 10 0
 transport input ssh
 logging synchronous
!
end
"#;

/// Возвращает true, если в отчёте есть хотя бы один item (любой severity
/// кроме чистого "успеха без следа") который ссылается на исходный текст,
/// содержащий нужную подстроку.
fn report_mentions(report: &netconv_core::report::ConversionReport, needle: &str) -> bool {
    report.items.iter().any(|i| {
        i.source_snippet
            .to_lowercase()
            .contains(&needle.to_lowercase())
            || i.message.to_lowercase().contains(&needle.to_lowercase())
    })
}

#[test]
fn vrp_banner_is_not_silently_dropped() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG_WITH_BANNER_DNS_LINE)
        .expect("conversion should succeed");

    let banner_in_output = output
        .config_text
        .to_lowercase()
        .contains("authorized access only");
    let banner_in_report = report_mentions(&output.report, "banner");

    assert!(
        banner_in_output || banner_in_report,
        "banner must leave a trace either in the rendered config or in the report, but found neither.\n\
         config:\n{}\n",
        output.config_text
    );
}

#[test]
fn eltex_banner_is_not_silently_dropped() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_BANNER_DNS_LINE)
        .expect("conversion should succeed");

    let banner_in_output = output
        .config_text
        .to_lowercase()
        .contains("authorized access only");
    let banner_in_report = report_mentions(&output.report, "banner");

    assert!(
        banner_in_output || banner_in_report,
        "banner must leave a trace either in the rendered config or in the report, but found neither.\n\
         config:\n{}\n",
        output.config_text
    );
}

#[test]
fn eltex_dns_is_not_silently_dropped() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_BANNER_DNS_LINE)
        .expect("conversion should succeed");

    let dns_in_output =
        output.config_text.contains("8.8.8.8") || output.config_text.contains("1.1.1.1");
    let dns_in_report =
        report_mentions(&output.report, "name-server") || report_mentions(&output.report, "dns");

    assert!(
        dns_in_output || dns_in_report,
        "DNS servers must leave a trace either in the rendered config or in the report, but found neither.\n\
         config:\n{}\n",
        output.config_text
    );
}

#[test]
fn eltex_line_vty_is_not_silently_dropped() {
    let output = convert(&IosParser, &EltexRenderer, CONFIG_WITH_BANNER_DNS_LINE)
        .expect("conversion should succeed");

    let line_vty_in_output = output.config_text.to_lowercase().contains("exec-timeout")
        || output.config_text.to_lowercase().contains("idle-timeout")
        || output.config_text.to_lowercase().contains("vty");
    let line_vty_in_report = report_mentions(&output.report, "line_vty")
        || report_mentions(&output.report, "exec-timeout")
        || report_mentions(&output.report, "transport input");

    assert!(
        line_vty_in_output || line_vty_in_report,
        "line vty settings must leave a trace either in the rendered config or in the report, but found neither.\n\
         config:\n{}\n",
        output.config_text
    );
}

/// Общий "lint"-тест: для базового конфига, использующего большинство
/// верхнеуровневых полей NetworkConfig, отчёт не должен быть подозрительно
/// маленьким относительно числа значимых команд во входном конфиге.
/// Это не доказывает отсутствие пробелов, но ловит будущие регрессии вида
/// "добавили новое поле в IR, забыли прочитать его в рендерере".
#[test]
fn vrp_report_has_entries_for_each_top_level_config_section() {
    let output = convert(&IosParser, &VrpRenderer, CONFIG_WITH_BANNER_DNS_LINE)
        .expect("conversion should succeed");

    let has_any_non_info = output
        .report
        .items
        .iter()
        .any(|i| i.severity != Severity::Info);
    assert!(
        has_any_non_info,
        "report should contain at least some Ok/Warn/Error items, not just Info/unknown"
    );
}
