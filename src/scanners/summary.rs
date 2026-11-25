use crate::utils::api::{get_all_issues, FalsePositives, Issue};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    fn parse(urgency: &str) -> Option<Self> {
        match urgency {
            "CR" => Some(Self::Critical),
            "HI" => Some(Self::High),
            "ME" => Some(Self::Medium),
            "LO" => Some(Self::Low),
            _ => None,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }

    fn sgr(self) -> &'static str {
        match self {
            Self::Critical => "38;5;203",
            Self::High => "38;5;208",
            Self::Medium => "38;5;220",
            Self::Low => "38;5;250",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Open,
    FixInProgress,
    Fixed,
    AcceptedRisk,
    FalsePositive,
    Duplicate,
}

struct StatusInfo {
    status: Status,
    wire: &'static str,
    key: &'static str,
    label: &'static str,
    meaning: &'static str,
}

const STATUSES: [StatusInfo; 6] = [
    StatusInfo {
        status: Status::Open,
        wire: "open",
        key: "open",
        label: "Open",
        meaning: "to fix; the scan page count",
    },
    StatusInfo {
        status: Status::FixInProgress,
        wire: "fix_in_progress",
        key: "fix_in_progress",
        label: "Fix in Progress",
        meaning: "a fix is underway",
    },
    StatusInfo {
        status: Status::Fixed,
        wire: "fixed",
        key: "fixed",
        label: "Fixed",
        meaning: "resolved",
    },
    StatusInfo {
        status: Status::AcceptedRisk,
        wire: "accepted_risk",
        key: "accepted_risk",
        label: "Accepted Risk",
        meaning: "risk accepted by your team",
    },
    StatusInfo {
        status: Status::FalsePositive,
        wire: "false_positive",
        key: "false_positive",
        label: "False Positive",
        meaning: "not a real security issue",
    },
    StatusInfo {
        status: Status::Duplicate,
        wire: "duplicate",
        key: "duplicate",
        label: "Duplicate",
        meaning: "same as another finding",
    },
];

impl Status {
    fn index(self) -> usize {
        match self {
            Self::Open => 0,
            Self::FixInProgress => 1,
            Self::Fixed => 2,
            Self::AcceptedRisk => 3,
            Self::FalsePositive => 4,
            Self::Duplicate => 5,
        }
    }

    fn parse(status: &str) -> Option<Self> {
        STATUSES
            .iter()
            .find(|info| info.wire == status)
            .map(|info| info.status)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeverityCounts([usize; Severity::ALL.len()]);

impl SeverityCounts {
    pub fn get(&self, severity: Severity) -> usize {
        self.0[severity.index()]
    }

    fn add(&mut self, severity: Severity) {
        self.0[severity.index()] += 1;
    }

    pub fn total(&self) -> usize {
        self.0.iter().sum()
    }

    fn json(&self) -> Value {
        let mut map = Map::new();
        for severity in Severity::ALL {
            map.insert(severity.key().into(), self.get(severity).into());
        }
        map.insert("total".into(), self.total().into());
        Value::Object(map)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RecentScanReuse {
    #[default]
    NotRequested,
    NotReused,
    Reused,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanInfo {
    pub id: String,
    pub project: String,
    pub branch: Option<String>,
    pub git_sha: Option<String>,
    pub reused_recent_scan: RecentScanReuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    NotRequested,
    Passed { condition: String },
    Failed { condition: String, tripped: usize },
}

impl Gate {
    pub fn exit_code(&self) -> i32 {
        match self {
            Gate::Failed { .. } => 1,
            Gate::NotRequested | Gate::Passed { .. } => 0,
        }
    }

    fn result(&self) -> &'static str {
        match self {
            Gate::NotRequested => "none",
            Gate::Passed { .. } => "pass",
            Gate::Failed { .. } => "fail",
        }
    }

    fn condition(&self) -> &str {
        match self {
            Gate::NotRequested => "",
            Gate::Passed { condition } | Gate::Failed { condition, .. } => condition,
        }
    }

    fn tripped(&self) -> usize {
        match self {
            Gate::Failed { tripped, .. } => *tripped,
            Gate::NotRequested | Gate::Passed { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRow {
    pub id: String,
    pub severity: Severity,
    pub cwe: String,
    pub title: String,
    pub path: String,
    pub line: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unrecognized {
    pub count: usize,
    pub values: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub scan: ScanInfo,
    pub gate: Gate,
    by_status: [SeverityCounts; STATUSES.len()],
    pub unrecognized: Unrecognized,
    pub fix_first: Vec<IssueRow>,
    pub results_url: String,
}

const FIX_FIRST_LIMIT: usize = 5;

const CODE_ROW_LABEL: &str = "SAST, Logic & Auth, Secrets";

fn is_false_positive(issue: &Issue) -> bool {
    issue.status == "false_positive"
        || issue.auto_triage.false_positive_detection.status == "false_positive"
}

fn classify(issue: &Issue) -> Result<(Status, Severity), Vec<String>> {
    let status = if is_false_positive(issue) {
        Some(Status::FalsePositive)
    } else {
        Status::parse(&issue.status)
    };
    let severity = Severity::parse(&issue.urgency);
    match (status, severity) {
        (Some(status), Some(severity)) => Ok((status, severity)),
        _ => {
            let mut unknown = Vec::new();
            if status.is_none() {
                unknown.push(format!("status={}", issue.status));
            }
            if severity.is_none() {
                unknown.push(format!("urgency={}", issue.urgency));
            }
            Err(unknown)
        }
    }
}

pub fn legacy_urgency_counts(issues: &[Issue]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for issue in issues.iter().filter(|issue| !is_false_positive(issue)) {
        *counts.entry(issue.urgency.clone()).or_insert(0) += 1;
    }
    counts
}

pub struct ScanIssues(Vec<Issue>);

impl ScanIssues {
    pub fn fetch(
        url: &str,
        project: &str,
        scan_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        get_all_issues(url, project, Some(scan_id.into()), FalsePositives::Include).map(Self)
    }

    #[cfg(test)]
    pub fn including_false_positives(issues: Vec<Issue>) -> Self {
        Self(issues)
    }

    pub fn as_slice(&self) -> &[Issue] {
        &self.0
    }
}

impl ScanSummary {
    pub fn build(scan: ScanInfo, gate: Gate, issues: &ScanIssues, results_url: String) -> Self {
        let mut by_status = [SeverityCounts::default(); STATUSES.len()];
        let mut unrecognized = Unrecognized::default();
        let mut open = Vec::new();
        for issue in issues.as_slice() {
            match classify(issue) {
                Ok((status, severity)) => {
                    by_status[status.index()].add(severity);
                    if status == Status::Open {
                        open.push(IssueRow {
                            id: issue.id.clone(),
                            severity,
                            cwe: issue.classification.id.clone(),
                            title: issue.classification.name.clone(),
                            path: issue.location.file.path.clone(),
                            line: issue.location.line_number,
                        });
                    }
                }
                Err(values) => {
                    unrecognized.count += 1;
                    unrecognized.values.extend(values);
                }
            }
        }
        open.sort_by(|a, b| {
            (a.severity, &a.path, a.line, &a.id).cmp(&(b.severity, &b.path, b.line, &b.id))
        });
        open.truncate(FIX_FIRST_LIMIT);
        ScanSummary {
            scan,
            gate,
            by_status,
            unrecognized,
            fix_first: open,
            results_url,
        }
    }

    pub fn counts(&self, status: Status) -> SeverityCounts {
        self.by_status[status.index()]
    }

    pub fn total_findings(&self) -> usize {
        self.by_status
            .iter()
            .map(SeverityCounts::total)
            .sum::<usize>()
            + self.unrecognized.count
    }

    fn all_statuses(&self) -> SeverityCounts {
        let mut all = SeverityCounts::default();
        for counts in &self.by_status {
            for (slot, count) in all.0.iter_mut().zip(counts.0) {
                *slot += count;
            }
        }
        all
    }
}

const TOTAL_HEADER: &str = "Total";
const LABEL_MIN_WIDTH: usize = 24;
const CELL_GAP: usize = 2;

const PLAIN: &str = "";
const BOLD: &str = "1";
const DIM: &str = "2";
const GREEN: &str = "32";
const RED: &str = "31";
const LINK: &str = "38;5;75;4";

struct Ledger {
    color: bool,
    label_width: usize,
}

impl Ledger {
    fn paint(&self, text: &str, sgr: &str) -> String {
        if self.color && !sgr.is_empty() {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn width(&self) -> usize {
        self.label_width
            + Severity::ALL
                .iter()
                .map(|severity| severity.label().len() + CELL_GAP)
                .sum::<usize>()
            + TOTAL_HEADER.len()
            + CELL_GAP
    }

    fn label(&self, text: &str, sgr: &str) -> String {
        let pad = self.label_width.saturating_sub(text.len());
        format!("{}{}", self.paint(text, sgr), " ".repeat(pad))
    }

    fn cell(&self, header: &str, text: &str, sgr: &str) -> String {
        let pad = (header.len() + CELL_GAP).saturating_sub(text.len());
        format!("{}{}", " ".repeat(pad), self.paint(text, sgr))
    }

    fn rule(&self) -> String {
        format!("{}\n", self.paint(&"-".repeat(self.width()), DIM))
    }

    fn header(&self, title: &str) -> String {
        let mut out = self.label(title, BOLD);
        for severity in Severity::ALL {
            out.push_str(&self.cell(severity.label(), severity.label(), severity.sgr()));
        }
        out.push_str(&self.cell(TOTAL_HEADER, TOTAL_HEADER, BOLD));
        out.push('\n');
        out
    }

    fn row(&self, label: &str, label_sgr: &str, counts: &SeverityCounts) -> String {
        let mut out = self.label(label, label_sgr);
        for severity in Severity::ALL {
            let count = counts.get(severity);
            let sgr = if count == 0 { DIM } else { severity.sgr() };
            out.push_str(&self.cell(severity.label(), &count.to_string(), sgr));
        }
        out.push_str(&self.cell(TOTAL_HEADER, &counts.total().to_string(), BOLD));
        out.push('\n');
        out
    }

    fn table(
        &self,
        title: &str,
        rows: &[(&str, SeverityCounts)],
        total: (&str, SeverityCounts),
    ) -> String {
        let mut out = self.header(title);
        out.push_str(&self.rule());
        for (label, counts) in rows {
            out.push_str(&self.row(label, PLAIN, counts));
        }
        out.push_str(&self.rule());
        out.push_str(&self.row(total.0, BOLD, &total.1));
        out
    }
}

pub fn render_human(summary: &ScanSummary, color: bool) -> String {
    const OPEN_TITLE: &str = "Open issues";
    const OPEN_TOTAL: &str = "Total open";
    const STATUS_TITLE: &str = "All findings by status";
    const STATUS_TOTAL: &str = "Total";

    let open_rows = vec![(CODE_ROW_LABEL, summary.counts(Status::Open))];
    let status_rows: Vec<(&str, SeverityCounts)> = STATUSES
        .iter()
        .map(|info| (info.label, summary.counts(info.status)))
        .collect();
    let longest_label = [OPEN_TITLE, OPEN_TOTAL, STATUS_TITLE, STATUS_TOTAL]
        .into_iter()
        .chain(
            open_rows
                .iter()
                .chain(&status_rows)
                .map(|(label, _)| *label),
        )
        .map(str::len)
        .max()
        .unwrap_or(0);
    let ledger = Ledger {
        color,
        label_width: (longest_label + 1).max(LABEL_MIN_WIDTH),
    };

    let scan = &summary.scan;
    let open = summary.counts(Status::Open).total();
    let total = summary.total_findings();
    let mut title = format!("Scan complete: {}", scan.project);
    if let Some(branch) = &scan.branch {
        title.push_str(&format!(", branch {branch}"));
    }
    title.push_str(&format!(", scan {}", scan.id));
    let mut out = format!("\n{}\n", ledger.paint(&title, BOLD));
    if scan.reused_recent_scan == RecentScanReuse::Reused {
        out.push_str("Reused a recent scan of this commit.\n");
    }
    out.push_str(&format!(
        "{total} findings in this scan: {}, {} in other states.\n\n",
        ledger.paint(&format!("{open} open"), BOLD),
        total - open
    ));

    out.push_str(&ledger.table(
        OPEN_TITLE,
        &open_rows,
        (OPEN_TOTAL, summary.counts(Status::Open)),
    ));
    out.push('\n');
    out.push_str(&ledger.table(
        STATUS_TITLE,
        &status_rows,
        (STATUS_TOTAL, summary.all_statuses()),
    ));

    if summary.unrecognized.count > 0 {
        out.push_str(&format!(
            "\n{} more finding(s) have a value this CLI does not recognize ({}). They count in the total above only; update the CLI to see them in a row.\n",
            summary.unrecognized.count,
            unrecognized_list(&summary.unrecognized)
        ));
    }

    match &summary.gate {
        Gate::NotRequested => {}
        Gate::Passed { condition } => out.push_str(&format!(
            "\n{} {condition}\n",
            ledger.paint("Gate passed:", GREEN)
        )),
        Gate::Failed { condition, tripped } => out.push_str(&format!(
            "\n{} {condition} matched {tripped} finding(s). Exiting with code {}.\n",
            ledger.paint("Gate failed:", RED),
            summary.gate.exit_code()
        )),
    }

    out.push_str(&format!(
        "\n{}{}{}\n",
        ledger.paint("Go to ", DIM),
        ledger.paint(&summary.results_url, LINK),
        ledger.paint(" to see results.", DIM)
    ));
    out
}

fn unrecognized_list(unrecognized: &Unrecognized) -> String {
    unrecognized
        .values
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ")
}

fn tsv_cell(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

pub fn render_agent(summary: &ScanSummary) -> String {
    let gate = &summary.gate;
    let scan = &summary.scan;
    let mut out = String::new();
    out.push_str("record\tresult\texit_code\tcondition\ttripped\n");
    out.push_str(&format!(
        "gate\t{}\t{}\t{}\t{}\n",
        gate.result(),
        gate.exit_code(),
        tsv_cell(gate.condition()),
        gate.tripped()
    ));
    out.push_str("record\tid\tproject\tbranch\tgit_sha\treused_recent_scan\tresults_url\n");
    out.push_str(&format!(
        "scan\t{}\t{}\t{}\t{}\t{}\t{}\n",
        tsv_cell(&scan.id),
        tsv_cell(&scan.project),
        tsv_cell(scan.branch.as_deref().unwrap_or("")),
        tsv_cell(scan.git_sha.as_deref().unwrap_or("")),
        match scan.reused_recent_scan {
            RecentScanReuse::NotRequested => "",
            RecentScanReuse::NotReused => "false",
            RecentScanReuse::Reused => "true",
        },
        tsv_cell(&summary.results_url)
    ));
    let open = summary.counts(Status::Open);
    out.push_str("record\tseverity\topen\n");
    for severity in Severity::ALL {
        out.push_str(&format!(
            "severity\t{}\t{}\n",
            severity.key(),
            open.get(severity)
        ));
    }
    out.push_str("record\tstatus\tcritical\thigh\tmedium\tlow\ttotal\tmeaning\n");
    for info in &STATUSES {
        let counts = summary.counts(info.status);
        out.push_str(&format!("status\t{}", info.key));
        for severity in Severity::ALL {
            out.push_str(&format!("\t{}", counts.get(severity)));
        }
        out.push_str(&format!("\t{}\t{}\n", counts.total(), info.meaning));
    }
    if summary.unrecognized.count > 0 {
        out.push_str("record\tcount\tvalues\n");
        out.push_str(&format!(
            "unrecognized\t{}\t{}\n",
            summary.unrecognized.count,
            tsv_cell(&unrecognized_list(&summary.unrecognized))
        ));
    }
    if !summary.fix_first.is_empty() {
        out.push_str("record\tid\tseverity\tcwe\ttitle\tlocation\n");
        for row in &summary.fix_first {
            out.push_str(&format!(
                "issue\t{}\t{}\t{}\t{}\t{}:{}\n",
                tsv_cell(&row.id),
                row.severity.key(),
                tsv_cell(&row.cwe),
                tsv_cell(&row.title),
                tsv_cell(&row.path),
                row.line
            ));
        }
    }
    out
}

pub fn agent_hints(summary: &ScanSummary) -> String {
    let issue_id = summary
        .fix_first
        .first()
        .map(|row| row.id.as_str())
        .unwrap_or("<ISSUE_ID>");
    format!(
        "Hint: Run `corgea ls --issues --scan-id {scan} --json` to list every finding in this scan.\n\
         Hint: Run `corgea inspect --issue {issue_id}` to read one finding.\n\
         Hint: Run `corgea inspect --issue --diff {issue_id}` to see its suggested fix.\n",
        scan = summary.scan.id
    )
}

pub fn render_json(summary: &ScanSummary) -> String {
    let scan = &summary.scan;
    let mut scan_json = json!({
        "id": scan.id,
        "project": scan.project,
        "branch": scan.branch,
        "git_sha": scan.git_sha,
    });
    match scan.reused_recent_scan {
        RecentScanReuse::NotRequested => {}
        RecentScanReuse::NotReused => scan_json["reused_recent_scan"] = false.into(),
        RecentScanReuse::Reused => scan_json["reused_recent_scan"] = true.into(),
    }
    let gate = &summary.gate;
    let mut by_status = Map::new();
    for info in &STATUSES {
        by_status.insert(info.key.into(), summary.counts(info.status).json());
    }
    let fix_first: Vec<Value> = summary
        .fix_first
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "severity": row.severity.key(),
                "cwe": row.cwe,
                "title": row.title,
                "path": row.path,
                "line": row.line,
            })
        })
        .collect();
    let document = json!({
        "schema_version": 1,
        "scan": scan_json,
        "gate": {
            "result": gate.result(),
            "exit_code": gate.exit_code(),
            "condition": match gate {
                Gate::NotRequested => Value::Null,
                _ => gate.condition().into(),
            },
            "tripped": gate.tripped(),
        },
        "total_findings": summary.total_findings(),
        "by_status": by_status,
        "unrecognized": {
            "count": summary.unrecognized.count,
            "values": summary.unrecognized.values,
        },
        "fix_first": fix_first,
        "results_url": summary.results_url,
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&document).expect("serialize summary")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::api::{
        AutoTriage, Classification, CorgeaFile, FalsePositiveDetection, Location, Project,
    };

    fn issue(id: &str, status: &str, urgency: &str, path: &str, line: u32) -> Issue {
        Issue {
            id: id.into(),
            scan_id: None,
            status: status.into(),
            urgency: urgency.into(),
            created_at: String::new(),
            classification: Classification {
                id: "CWE-89".into(),
                name: "SQL Injection".into(),
                description: None,
            },
            location: Location {
                file: CorgeaFile {
                    name: String::new(),
                    language: String::new(),
                    path: path.into(),
                },
                line_number: line,
                project: Project {
                    name: String::new(),
                    branch: None,
                    git_sha: None,
                },
            },
            details: None,
            auto_triage: AutoTriage {
                false_positive_detection: FalsePositiveDetection {
                    status: "valid".into(),
                    reasoning: None,
                },
            },
            auto_fix_suggestion: None,
            scanner_metadata: None,
            metadata: None,
        }
    }

    fn held_false_positive(id: &str, urgency: &str) -> Issue {
        let mut issue = issue(id, "open", urgency, "src/held.js", 1);
        issue.auto_triage.false_positive_detection.status = "false_positive".into();
        issue
    }

    fn mixed_issues() -> Vec<Issue> {
        vec![
            issue("o1", "open", "HI", "src/b.js", 9),
            issue("o2", "open", "CR", "src/z.js", 1),
            issue("p1", "fix_in_progress", "HI", "src/a.js", 1),
            issue("f1", "fixed", "CR", "src/a.js", 2),
            issue("a1", "accepted_risk", "ME", "src/a.js", 3),
            issue("d1", "duplicate", "LO", "src/a.js", 4),
            issue("fp1", "false_positive", "HI", "src/a.js", 5),
            held_false_positive("fp2", "ME"),
        ]
    }

    fn scan_info() -> ScanInfo {
        ScanInfo {
            id: "scan-1".into(),
            project: "goof".into(),
            branch: Some("main".into()),
            git_sha: Some("abc123".into()),
            reused_recent_scan: RecentScanReuse::NotRequested,
        }
    }

    fn summary_of(issues: Vec<Issue>, gate: Gate) -> ScanSummary {
        ScanSummary::build(
            scan_info(),
            gate,
            &ScanIssues::including_false_positives(issues),
            "https://corgea.test/scan".into(),
        )
    }

    #[test]
    fn count_slots_follow_the_listed_order() {
        for (slot, severity) in Severity::ALL.iter().enumerate() {
            assert_eq!(severity.index(), slot, "{severity:?}");
        }
        for (slot, info) in STATUSES.iter().enumerate() {
            assert_eq!(info.status.index(), slot, "{:?}", info.status);
        }
    }

    #[test]
    fn open_counts_only_open_findings() {
        let summary = summary_of(mixed_issues(), Gate::NotRequested);
        let open = summary.counts(Status::Open);
        assert_eq!(open.get(Severity::Critical), 1);
        assert_eq!(open.get(Severity::High), 1);
        assert_eq!(open.total(), 2);
        assert_eq!(summary.counts(Status::FalsePositive).total(), 2);
        assert_eq!(summary.counts(Status::AcceptedRisk).total(), 1);
        assert_eq!(summary.total_findings(), 8);
    }

    #[test]
    fn legacy_counts_keep_every_status_but_false_positives() {
        let counts = legacy_urgency_counts(&mixed_issues());
        assert_eq!(counts.get("CR"), Some(&2));
        assert_eq!(counts.get("HI"), Some(&2));
        assert_eq!(counts.get("ME"), Some(&1));
        assert_eq!(counts.get("LO"), Some(&1));
    }

    #[test]
    fn unknown_status_or_urgency_is_counted_and_named() {
        let issues = vec![
            issue("o1", "open", "HI", "a", 1),
            issue("x1", "snoozed", "HI", "a", 2),
            issue("x2", "open", "IN", "a", 3),
        ];
        let summary = summary_of(issues, Gate::NotRequested);
        assert_eq!(summary.counts(Status::Open).total(), 1);
        assert_eq!(summary.unrecognized.count, 2);
        assert_eq!(summary.total_findings(), 3);
        assert!(render_human(&summary, false).contains("status=snoozed, urgency=IN"));
        assert!(render_agent(&summary).contains("unrecognized\t2\tstatus=snoozed, urgency=IN\n"));
        let json: Value = serde_json::from_str(&render_json(&summary)).unwrap();
        assert_eq!(json["unrecognized"]["count"], 2);
    }

    #[test]
    fn fix_first_is_critical_first_then_path_then_line_and_capped() {
        let issues = vec![
            issue("h-b", "open", "HI", "src/b.js", 1),
            issue("h-a2", "open", "HI", "src/a.js", 20),
            issue("h-a1", "open", "HI", "src/a.js", 3),
            issue("l", "open", "LO", "src/a.js", 1),
            issue("c", "open", "CR", "src/z.js", 1),
            issue("m", "open", "ME", "src/a.js", 1),
            issue("fixed", "fixed", "CR", "src/a.js", 1),
        ];
        let summary = summary_of(issues, Gate::NotRequested);
        let ids: Vec<&str> = summary.fix_first.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["c", "h-a1", "h-a2", "h-b", "m"]);
    }

    #[test]
    fn human_prints_every_status_row_with_zeros() {
        let issues = vec![issue("o1", "open", "HI", "src/a.js", 1)];
        let out = render_human(&summary_of(issues, Gate::NotRequested), false);
        let expected = "
Scan complete: goof, branch main, scan scan-1
1 findings in this scan: 1 open, 0 in other states.

Open issues                   Critical  High  Medium  Low  Total
----------------------------------------------------------------
SAST, Logic & Auth, Secrets          0     1       0    0      1
----------------------------------------------------------------
Total open                           0     1       0    0      1

All findings by status        Critical  High  Medium  Low  Total
----------------------------------------------------------------
Open                                 0     1       0    0      1
Fix in Progress                      0     0       0    0      0
Fixed                                0     0       0    0      0
Accepted Risk                        0     0       0    0      0
False Positive                       0     0       0    0      0
Duplicate                            0     0       0    0      0
----------------------------------------------------------------
Total                                0     1       0    0      1

Go to https://corgea.test/scan to see results.
";
        assert_eq!(out, expected);
        assert!(out.is_ascii());
    }

    #[test]
    fn human_colors_cells_by_severity_and_bolds_totals() {
        let summary = summary_of(mixed_issues(), Gate::NotRequested);
        let colored = render_human(&summary, true);
        let code_row = concat!(
            "SAST, Logic & Auth, Secrets ",
            "         \x1b[38;5;203m1\x1b[0m",
            "     \x1b[38;5;208m1\x1b[0m",
            "       \x1b[2m0\x1b[0m",
            "    \x1b[2m0\x1b[0m",
            "      \x1b[1m2\x1b[0m\n",
        );
        assert!(colored.contains(code_row), "{colored}");
        assert!(colored.contains("\x1b[1mTotal open\x1b[0m"), "{colored}");
        let plain = regex::Regex::new("\x1b\\[[0-9;]*m")
            .unwrap()
            .replace_all(&colored, "");
        assert_eq!(plain, render_human(&summary, false));
    }

    #[test]
    fn agent_output_starts_with_the_result_record() {
        let gate = Gate::Failed {
            condition: "--fail-on HI".into(),
            tripped: 3,
        };
        let out = render_agent(&summary_of(mixed_issues(), gate));
        let expected = "record\tresult\texit_code\tcondition\ttripped
gate\tfail\t1\t--fail-on HI\t3
record\tid\tproject\tbranch\tgit_sha\treused_recent_scan\tresults_url
scan\tscan-1\tgoof\tmain\tabc123\t\thttps://corgea.test/scan
record\tseverity\topen
severity\tcritical\t1
severity\thigh\t1
severity\tmedium\t0
severity\tlow\t0
record\tstatus\tcritical\thigh\tmedium\tlow\ttotal\tmeaning
status\topen\t1\t1\t0\t0\t2\tto fix; the scan page count
status\tfix_in_progress\t0\t1\t0\t0\t1\ta fix is underway
status\tfixed\t1\t0\t0\t0\t1\tresolved
status\taccepted_risk\t0\t0\t1\t0\t1\trisk accepted by your team
status\tfalse_positive\t0\t1\t1\t0\t2\tnot a real security issue
status\tduplicate\t0\t0\t0\t1\t1\tsame as another finding
record\tid\tseverity\tcwe\ttitle\tlocation
issue\to2\tcritical\tCWE-89\tSQL Injection\tsrc/z.js:1
issue\to1\thigh\tCWE-89\tSQL Injection\tsrc/b.js:9
";
        assert_eq!(out, expected);
        assert!(!out.contains('\x1b') && !out.contains('\r'));
    }

    #[test]
    fn json_document_mirrors_the_summary() {
        let mut scan = scan_info();
        scan.reused_recent_scan = RecentScanReuse::Reused;
        let summary = ScanSummary::build(
            scan,
            Gate::Passed {
                condition: "--block-on criticals".into(),
            },
            &ScanIssues::including_false_positives(mixed_issues()),
            "https://corgea.test/scan".into(),
        );
        let json: Value = serde_json::from_str(&render_json(&summary)).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["scan"]["reused_recent_scan"], true);
        assert_eq!(json["gate"]["result"], "pass");
        assert_eq!(json["gate"]["exit_code"], 0);
        assert_eq!(json["by_status"]["open"]["total"], 2);
        assert_eq!(json["by_status"]["duplicate"]["low"], 1);
        assert_eq!(json["by_status"]["false_positive"]["medium"], 1);
        assert_eq!(json["fix_first"][0]["severity"], "critical");
        assert_eq!(json["total_findings"], 8);
    }

    #[test]
    fn json_omits_reuse_when_the_flag_was_not_passed() {
        let json: Value =
            serde_json::from_str(&render_json(&summary_of(vec![], Gate::NotRequested))).unwrap();
        assert!(json["scan"].get("reused_recent_scan").is_none());
        assert_eq!(json["gate"]["result"], "none");
        assert_eq!(json["gate"]["condition"], Value::Null);
    }
}
