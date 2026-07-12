pub mod ir;
pub mod profile;
pub mod report;
pub mod traits;

pub use ir::*;
pub use profile::{DeviceProfile, DomainMismatch, detect_domain_mismatches};
pub use report::{ConversionReport, ReportSummary, ReportItem, Severity, RiskScore, RiskLevel, ConfidenceLevel};
pub use traits::*;
