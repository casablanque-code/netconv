use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ConversionReport — главная ценность инструмента
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversionReport {
    pub source_vendor: String,
    pub target_vendor: String,
    pub summary: ReportSummary,
    pub items: Vec<ReportItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_commands: usize,
    pub exact: usize,
    pub approximate: usize,
    pub manual_required: usize,
    pub unknown: usize,
}

impl ReportSummary {
    pub fn exact_pct(&self) -> f32 {
        if self.total_commands == 0 { return 0.0; }
        self.exact as f32 / self.total_commands as f32 * 100.0
    }

    pub fn coverage_pct(&self) -> f32 {
        if self.total_commands == 0 { return 0.0; }
        (self.exact + self.approximate) as f32 / self.total_commands as f32 * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub severity: Severity,
    pub category: String,
    pub source_snippet: String,
    pub target_snippet: Option<String>,
    pub message: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    /// OK — конвертировано точно
    Ok,
    /// Warn — есть нюанс, проверь поведение
    Warn,
    /// Error — нет аналога, нужно ручное решение
    Error,
    /// Info — нераспознанная команда, игнорирована
    Info,
}

impl ConversionReport {
    pub fn new(source_vendor: &str, target_vendor: &str) -> Self {
        ConversionReport {
            source_vendor: source_vendor.to_string(),
            target_vendor: target_vendor.to_string(),
            ..Default::default()
        }
    }

    pub fn add_exact(&mut self, category: &str, source: &str, target: &str) {
        self.summary.exact += 1;
        self.summary.total_commands += 1;
        self.items.push(ReportItem {
            severity: Severity::Ok,
            category: category.to_string(),
            source_snippet: source.to_string(),
            target_snippet: Some(target.to_string()),
            message: "Точное соответствие".to_string(),
            recommendation: None,
        });
    }

    pub fn add_approximate(&mut self, category: &str, source: &str, target: &str, note: &str) {
        self.summary.approximate += 1;
        self.summary.total_commands += 1;
        self.items.push(ReportItem {
            severity: Severity::Warn,
            category: category.to_string(),
            source_snippet: source.to_string(),
            target_snippet: Some(target.to_string()),
            message: note.to_string(),
            recommendation: None,
        });
    }

    pub fn add_manual(&mut self, category: &str, source: &str, reason: &str, rec: Option<&str>) {
        self.summary.manual_required += 1;
        self.summary.total_commands += 1;
        self.items.push(ReportItem {
            severity: Severity::Error,
            category: category.to_string(),
            source_snippet: source.to_string(),
            target_snippet: None,
            message: reason.to_string(),
            recommendation: rec.map(|s| s.to_string()),
        });
    }

    pub fn add_unknown(&mut self, raw: &str, context: &str) {
        self.summary.unknown += 1;
        self.summary.total_commands += 1;
        self.items.push(ReportItem {
            severity: Severity::Info,
            category: "unknown".to_string(),
            source_snippet: raw.to_string(),
            target_snippet: None,
            message: format!("Нераспознанная команда в контексте: {}", context),
            recommendation: None,
        });
    }

    /// Только items с severity >= Warn — для краткого вывода
    pub fn warnings_and_errors(&self) -> Vec<&ReportItem> {
        self.items.iter()
            .filter(|i| i.severity != Severity::Ok && i.severity != Severity::Info)
            .collect()
    }
}
