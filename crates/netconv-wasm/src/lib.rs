use wasm_bindgen::prelude::*;
use netconv_parser_ios::IosParser;
use netconv_render_vrp::VrpRenderer;
use netconv_render_eltex::EltexRenderer;
use serde::{Deserialize, Serialize};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Результат конвертации — передаётся в JS как JSON
#[derive(Serialize, Deserialize)]
pub struct WasmConvertResult {
    pub success: bool,
    pub config_text: String,
    pub report: WasmReport,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WasmReport {
    pub source_vendor: String,
    pub target_vendor: String,
    pub total: usize,
    pub exact: usize,
    pub approximate: usize,
    pub manual_required: usize,
    pub unknown: usize,
    pub exact_pct: f32,
    pub coverage_pct: f32,
    pub items: Vec<WasmReportItem>,
    pub risk_level: String,
    pub risk_reasons: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct WasmReportItem {
    pub severity: String,
    pub category: String,
    pub source_snippet: String,
    pub target_snippet: Option<String>,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Основная функция — вызывается из JS
/// convert_config(source_config: string, source_vendor: string, target_vendor: string) → JSON string
#[wasm_bindgen]
pub fn convert_config(
    source_config: &str,
    source_vendor: &str,
    target_vendor: &str,
) -> String {
    let result = run_conversion(source_config, source_vendor, target_vendor);
    serde_json::to_string(&result).unwrap_or_else(|e| {
        format!("{{\"success\":false,\"error\":\"{}\"}}", e)
    })
}

fn run_conversion(input: &str, source: &str, target: &str) -> WasmConvertResult {
    match (source, target) {
        ("ios", "vrp") | ("cisco", "huawei") => {
            do_convert(&IosParser, &VrpRenderer, input, source, target)
        }
        ("ios", "eltex") => {
            do_convert(&IosParser, &EltexRenderer, input, source, target)
        }
        _ => WasmConvertResult {
            success: false,
            config_text: String::new(),
            report: empty_report(source, target),
            error: Some(format!("Pair {}->{} not yet supported", source, target)),
        }
    }
}

fn do_convert<P, R>(
    parser: &P,
    renderer: &R,
    input: &str,
    source: &str,
    target: &str,
) -> WasmConvertResult
where
    P: netconv_core::traits::ConfigParser,
    R: netconv_core::traits::ConfigRenderer,
{
    match netconv_core::traits::convert(parser, renderer, input) {
        Ok(output) => {
            let r = &output.report;
            WasmConvertResult {
                success: true,
                config_text: output.config_text,
                report: WasmReport {
                    source_vendor: r.source_vendor.clone(),
                    target_vendor: r.target_vendor.clone(),
                    total:           r.summary.total_commands,
                    exact:           r.summary.exact,
                    approximate:     r.summary.approximate,
                    manual_required: r.summary.manual_required,
                    unknown:         r.summary.unknown,
                    exact_pct:       r.summary.exact_pct(),
                    coverage_pct:    r.summary.coverage_pct(),
                    items: r.items.iter().map(|item| WasmReportItem {
                        severity:       format!("{:?}", item.severity),
                        category:       item.category.clone(),
                        source_snippet: item.source_snippet.clone(),
                        target_snippet: item.target_snippet.clone(),
                        message:        item.message.clone(),
                        recommendation: item.recommendation.clone(),
                    }).collect(),
                    risk_level:   r.risk.level.label().to_string(),
                    risk_reasons: r.risk.reasons.clone(),
                },
                error: None,
            }
        }
        Err(e) => WasmConvertResult {
            success: false,
            config_text: String::new(),
            report: empty_report(source, target),
            error: Some(e.to_string()),
        }
    }
}

fn empty_report(src: &str, tgt: &str) -> WasmReport {
    WasmReport {
        source_vendor: src.to_string(),
        target_vendor: tgt.to_string(),
        total: 0, exact: 0, approximate: 0, manual_required: 0, unknown: 0,
        exact_pct: 0.0, coverage_pct: 0.0,
        items: vec![],
        risk_level: "LOW".to_string(),
        risk_reasons: vec![],
    }
}
