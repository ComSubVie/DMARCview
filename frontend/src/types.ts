export interface SourceExpectation {
  id: number;
  match_type: "ip" | "cidr" | "asn" | "domain";
  value: string;
  label: string | null;
  created_at: string | null;
}

export interface DomainProfile {
  name: string;
  display_name: string | null;
  notes: string | null;
  tags: string[];
}

export interface DomainRef {
  id: number;
  name: string;
  display_name: string;
}

export interface DomainSummary extends DomainRef {
  reports_30d: number;
  messages_30d: number;
  aligned_pct_30d: number | null;
  last_report_date: string | null;
  tls_reports: number;
  last_tls_date: string | null;
}

export interface Kpis {
  messages: number;
  sources: number;
  aligned: number;
  aligned_pct: number;
  failed: number;
  dkim_pass_messages: number;
  spf_only_messages: number;
  signed_messages: number;
  unsigned_messages: number;
  verified_sources: number;
  unverified_sources: number;
  verified_messages: number;
  unverified_messages: number;
  providers: number;
  sentences: string[];
}

export interface DailyPoint {
  date: string;
  aligned: number;
  failed: number;
  total: number;
}

export type CheckState = "pass" | "fail" | "none" | "mixed";

export interface Source {
  ip: string;
  ptr: string | null;
  fcrdns_status: "match" | "mismatch" | "none" | "unknown" | null;
  fcrdns_forward: string | null;
  messages: number;
  aligned: number;
  failed: number;
  verified: boolean;
  dmarc: CheckState;
  spf: CheckState;
  spf_aligned: CheckState;
  dkim: CheckState;
  dkim_aligned: CheckState;
  dkim_signed_messages: number;
  unsigned_messages: number;
  foreign_header_messages: number;
  country: { code: string | null; name: string | null; flag: string };
  first_seen: string;
  last_seen: string;
  header_from: string | null;
  envelope_from: string | null;
  providers: string[];
  dispositions: Record<string, number>;
}

export interface Country {
  code: string | null;
  name: string;
  flag: string;
  messages: number;
  aligned: number;
}

export interface Submitter {
  org: string;
  name: string;
  color: string;
  known: boolean;
  reports: number;
  messages: number;
}

export interface Policy {
  available: boolean;
  message?: string;
  p?: string;
  sp?: string;
  pct?: number;
  adkim?: string | null;
  aspf?: string | null;
  fo?: string | null;
  label?: string;
  enforced?: boolean;
  mode?: string;
  observed_since?: string | null;
  last_report_date?: string | null;
  variants?: { p: string; sp: string; pct: number; reports: number }[];
}

export interface AdviceOption {
  value: string;
  label: string;
  state: string;
  detail: string;
}

export interface SimulationSource {
  ip: string;
  header_from: string | null;
  messages: number;
  aligned: number;
  aligned_pct: number;
  failed: number;
  current_action: string;
  proposed_action: string;
  current_severity: number;
  proposed_severity: number;
  newly_affected: number;
  newly_blocked: number;
  already_affected: number;
  relaxed: number;
}

export interface PolicySimulation {
  available: boolean;
  domain: string;
  range: { start: string; end: string; days: number };
  message?: string;
  current: {
    p: string;
    sp: string;
    np: string;
    testing: string;
    label: string;
  } | null;
  proposed: {
    p: string;
    sp: string;
    np: string;
    testing: string;
    label: string;
  } | null;
  totals: {
    messages: number;
    aligned: number;
    failed: number;
    newly_affected: number;
    newly_blocked: number;
    newly_quarantined: number;
    already_affected: number;
    relaxed: number;
    unaffected: number;
    sources: number;
    affected_sources: number;
  };
  newly_affected_pct: number;
  affected_pct: number;
  sources: SimulationSource[];
  verdict: { level: "good" | "warn" | "bad" | "info"; label: string; detail: string };
  confidence: "low" | "medium" | "high";
  warnings: string[];
  caveats: string[];
  generated_at: string;
}

export interface TimelineItem {
  id: string;
  ref_id?: number;
  source: "annotation" | "alert" | "dns" | "identity" | "report_gap";
  kind: string;
  title: string;
  body: string | null;
  occurred_at: string | null;
  created_at?: string | null;
  editable: boolean;
}

export interface Timeline {
  domain: string;
  items: TimelineItem[];
  annotation_count: number;
}

export interface Advice {
  status: string;
  label: string;
  tone: "good" | "warn" | "info" | "bad";
  advice: string;
  options: AdviceOption[];
  days_observed: number;
}

export interface PolicyOverviewItem {
  domain: string;
  p: string;
  pct: number;
  messages: number;
  aligned_pct: number | null;
  last_report_date: string | null;
}

export interface Coverage {
  days_with_reports: number;
  days: number;
  pct: number;
  reports: number;
  last_ingested_at: string | null;
  domains: number;
}

export interface TlsSummary {
  sessions: number;
  success: number;
  failure: number;
  success_pct: number;
  reports: number;
  mx_hosts: number;
}

export interface FleetPoint {
  date: string;
  total: number;
  aligned: number;
}

export interface FleetItem {
  domain: string;
  display_name: string | null;
  messages: number;
  aligned: number;
  aligned_pct: number;
  failing_sources: number;
  sources: number;
  last_report: string | null;
  tls_pct: number | null;
  policy_p: string | null;
  policy_sp: string | null;
  health: string | null;
  health_score: number | null;
  health_checked_at: string | null;
  tags: string[];
  sparkline: FleetPoint[];
}

export interface Dashboard {
  domain: DomainRef | null;
  range: { start: string; end: string; days: number; label: string };
  kpis: Kpis;
  daily: DailyPoint[];
  sources: Source[];
  groups: { verified: { messages: number; sources: number }; unverified: { messages: number; sources: number } };
  countries: Country[];
  submitters: Submitter[];
  policy: Policy | null;
  policy_overview: PolicyOverviewItem[];
  coverage: Coverage;
  volume: { month_messages: number; alert_threshold: number; pct: number };
  tls: TlsSummary;
  advice: Advice;
  report_gaps: ReportGap[];
  identities: Identities;
  changes: Changes;
  anomaly: VolumeAnomaly;
  coverage_detail: CoverageDetail;
  fleet: FleetItem[];
  generated_at: string;
}

export interface VolumeAnomaly {
  available: boolean;
  z: number | null;
  median: number | null;
  latest: number | null;
  date: string | null;
  level: "high" | "normal" | "low";
}

export interface Identity {
  key: string;
  label: string;
  detail: string;
  messages: number;
  aligned: number;
  aligned_pct: number;
  dkim_pass: number;
  spf_pass: number;
  sources: number;
  first_seen: string | null;
  last_seen: string | null;
  network: string;
  country: string | null;
  country_code: string | null;
  ips: string[];
}

export interface Identities {
  total: number;
  items: Identity[];
}

export interface ChangeChip {
  key: string;
  label: string;
  display: string;
  tone: "good" | "warn" | "neutral";
}

export interface Changes {
  available: boolean;
  chips: ChangeChip[];
  new_identities: string[];
  lost_identities: string[];
}

export interface ReporterCoverage {
  org: string;
  reports: number;
  messages: number;
  last_report: string | null;
  days_since: number | null;
  days_present: number;
  coverage_pct: number;
  avg_latency_hours: number | null;
  warnings: number;
  quality_score: number;
  quality: "good" | "sparse" | "late" | "silent";
  status: "active" | "silent";
}

export interface SubdomainCoverage {
  domain: string;
  messages: number;
  aligned_pct: number;
  sources: number;
  last_seen: string | null;
  status: "covered" | "uncovered";
}

export interface PctPoint {
  date: string;
  pct: number;
}

export interface CoverageDetail {
  reporters: ReporterCoverage[];
  subdomains: SubdomainCoverage[];
  subdomain_policy: string | null;
  policy_source: "dmarcbis" | "reports" | null;
  pct_timeline: PctPoint[];
  pct_start: number | null;
  pct_latest: number | null;
  ramp_days: number | null;
}

export interface ReportGap {
  domain: string;
  hours: number;
  expected_hours: number;
  last_report: string;
}

export interface ReportRow {
  id: number;
  kind: "dmarc" | "tls";
  domain: string;
  org: string;
  org_name: string;
  org_color: string;
  report_id: string;
  date_begin: string;
  date_end: string;
  date: string;
  messages: number;
  aligned: number;
  failed: number;
  aligned_pct: number;
  records: number;
  sources: number;
  policy: string | null;
  source: string;
  errors?: number;
  ingested_at: string;
}

export interface ReportsPage {
  items: ReportRow[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface ReportRecord {
  ip: string;
  messages: number;
  aligned: boolean;
  dkim: string;
  spf: string;
  disposition: string | null;
  header_from: string | null;
  envelope_from: string | null;
  envelope_to: string | null;
  country: { code: string | null; name: string | null; flag: string };
  dkim_entries: { domain: string; selector: string; result: string }[];
  spf_entries: { domain: string; result: string }[];
  reason: { type: string | null; comment: string | null } | null;
}

export interface ReportDetail extends Omit<ReportRow, "aligned_pct" | "policy" | "records" | "sources" | "errors"> {
  message_count: number;
  aligned_count: number;
  failed_count: number;
  source_count: number;
  org_email: string | null;
  received_at: string | null;
  errors: string[];
  raw_sha256: string;
  policy: {
    domain: string | null;
    p: string | null;
    sp: string | null;
    np: string | null;
    pct: number | null;
    testing: string | null;
    discovery: string | null;
    adkim: string | null;
    aspf: string | null;
    fo: string | null;
  };
  records: ReportRecord[];
}

export interface TlsDaily {
  date: string;
  success: number;
  failure: number;
  total: number;
}

export interface TlsFailure {
  result_type: string;
  count: number;
  ips: string[];
  hosts: string[];
  reasons: string[];
  last_seen: string | null;
}

export interface TlsHost {
  host: string;
  success: number;
  failure: number;
  sessions: number;
  success_pct: number;
  policies: number;
}

export interface TlsReportRow {
  id: number;
  kind: "tls";
  domain: string;
  org: string;
  org_name: string;
  org_color: string;
  report_id: string;
  date_begin: string;
  date_end: string;
  date: string;
  success: number;
  failure: number;
  sessions: number;
  success_pct: number;
  source: string;
  ingested_at: string;
}

export interface TlsDashboard {
  domain: DomainRef | null;
  range: { start: string; end: string; days: number; label: string };
  kpis: TlsSummary & { submitters: number; reports: number };
  daily: TlsDaily[];
  policies: TlsHost[];
  failures: TlsFailure[];
  policy: {
    type: string | null;
    mode: string | null;
    domain: string | null;
    mx_hosts: string[];
    max_age: number | null;
    string: string[];
    observed_since: string | null;
  } | null;
  reports: TlsReportRow[];
  generated_at: string;
}

export interface TlsReportDetail extends TlsReportRow {
  contact_info: string | null;
  policy: {
    type: string | null;
    mode: string | null;
    domain: string | null;
    mx_hosts: string[];
    max_age: number | null;
    string: string[];
  };
  policies: { type: string | null; domain: string | null; mx_hosts: string[]; success: number; failure: number }[];
  failure_details: {
    result_type: string;
    mx: string | null;
    ip: string | null;
    count: number;
    reason: string | null;
    info: string | null;
    country: { code: string | null; name: string | null; flag: string };
  }[];
  raw_sha256: string;
}

export interface AuditItem {
  id: number;
  at: string | null;
  actor: string;
  action: string;
  domain: string | null;
  target: string | null;
  detail: Record<string, unknown>;
}

export interface Meta {
  version: string;
  app: string;
  jmap_enabled: boolean;
  jmap_mailbox: string;
  geoip: boolean;
  monthly_message_alert: number;
  domains: { name: string; display_name: string }[];
  domain_count: number;
}

export interface IngestRun {
  id: number;
  source: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  messages_seen: number;
  messages_ingested: number;
  reports_created: number;
  tls_reports_created: number;
  error: string | null;
}

export interface IngestStatus {
  configured: boolean;
  enabled: boolean;
  url: string;
  username: string;
  mailbox: string;
  poll_seconds: number;
  geoip: boolean;
  state: {
    running: boolean;
    trigger: string | null;
    started_at: string | null;
    finished_at: string | null;
    last_error: string | null;
    last_result: unknown;
  };
  counts: { reports: number; tls_reports: number; last_ingested_at: string | null };
  runs: IngestRun[];
}

export interface ProbeResult {
  ok: boolean;
  username?: string;
  account_name?: string;
  api_url?: string;
  mailboxes: { name: string; id: string; role: string | null }[];
  report_mailbox?: string | null;
  error?: string | null;
  mailbox_setting?: string;
}


export type HealthStatus = "pass" | "warn" | "fail" | "info" | "unknown" | "n/a";

export interface HealthCheckResult {
  key: string;
  label: string;
  status: HealthStatus;
  summary: string;
  details: string[];
  remediation: string | null;
  core: boolean;
  evidence: Record<string, unknown>;
  duration_ms: number;
}

export interface TransportProbeResult {
  id: number;
  host: string;
  port: number;
  mode: string;
  status: HealthStatus;
  tls_version: string | null;
  cipher: string | null;
  cert_subject: string | null;
  cert_issuer: string | null;
  not_after: string | null;
  days_left: number | null;
  hostname_ok: boolean | null;
  chain_ok: boolean | null;
  dane_status: string | null;
  details: Record<string, unknown>;
  error: string | null;
  checked_at: string;
  duration_ms: number;
}

export interface DomainHealth {
  domain: string;
  checked_at: string | null;
  overall: HealthStatus;
  score: number;
  core_passed: number;
  core_total: number;
  stale: boolean;
  results: HealthCheckResult[];
  duration_ms: number;
  error: string | null;
  probes: TransportProbeResult[];
  settings: DomainSettings;
  dkim_discovered: { domain: string; selector: string }[];
  history: {
    checked_at: string | null;
    overall: HealthStatus;
    score: number;
    core_passed: number;
    core_total: number;
  }[];
  checked: boolean;
}

export interface DnsDiffEntry {
  key: string;
  label: string;
  status: string;
  summary: string;
  record: string | null;
  evidence: Record<string, unknown>;
}

export interface DnsDiffChange {
  id: string;
  key: string;
  label: string;
  checked_at: string | null;
  before: DnsDiffEntry;
  after: DnsDiffEntry;
}

export interface DnsDiff {
  domain: string;
  current: DnsDiffEntry[];
  changes: DnsDiffChange[];
}

export interface DomainSettings {
  domain: string;
  dkim_selectors: string[];
  probe_targets: string[];
  expected_report_hours: number;
  dns_checks_enabled: boolean;
  checks_muted_until: string | null;
  updated_at: string | null;
}

export interface FleetViewFilters {
  tag?: string;
  policy?: string;
  health?: string;
  only_failing?: boolean;
  max_alignment?: string;
  max_tls?: string;
  sort_key?: string;
  sort_dir?: "asc" | "desc";
}

export interface SavedFleetView {
  id: number;
  name: string;
  filters: FleetViewFilters;
  created_at: string | null;
  updated_at: string | null;
}

export interface FleetHealthItem {
  domain: string;
  overall: HealthStatus;
  score: number;
  core_passed: number;
  core_total: number;
  checked_at: string | null;
  checked: boolean;
  stale: boolean;
  probes: number;
  failing_probes: number;
  next_expiry_days: number | null;
}

export interface StorageInfo {
  database_bytes: number;
  wal_bytes: number;
  raw_bytes: number;
  raw_xml_bytes: number;
  raw_json_bytes: number;
  total_bytes: number;
  reports: number;
  tls_reports: number;
  source_records: number;
  oldest_report: string | null;
  backups: { count: number; last_at: string | null };
  retention_days: number;
}

export interface ScheduledJob {
  name: string;
  label: string;
  interval_seconds: number;
  state: string;
  last_run: {
    started_at: string;
    finished_at: string | null;
    status: string;
    summary: Record<string, unknown>;
    error: string | null;
  } | null;
}

export interface JobsResponse {
  items: ScheduledJob[];
  scheduled: boolean;
}


export type AlertSeverity = "critical" | "warning" | "info";

export interface AlertFieldSpec {
  key: string;
  label: string;
  type: "int" | "float";
  default: number;
  min: number;
  max: number;
  unit: string;
}

export interface AlertKindSpec {
  kind: string;
  label: string;
  description: string;
  severity: AlertSeverity;
  fields: AlertFieldSpec[];
}

export interface AlertFieldSpec {
  key: string;
  label: string;
  type: "int" | "float";
  default: number;
  min: number;
  max: number;
  unit: string;
}

export interface AlertOverrideRule {
  rule_id: number;
  kind: string;
  label: string;
  description: string;
  enabled: boolean;
  condition: Record<string, number>;
  cooldown_minutes: number;
  fields: AlertFieldSpec[];
  override: {
    enabled: boolean;
    condition: Record<string, number>;
    cooldown_minutes: number;
  } | null;
}

export interface AlertRuleItem {
  id: number;
  kind: string;
  label: string;
  description: string;
  severity: AlertSeverity;
  enabled: boolean;
  condition: Record<string, number>;
  cooldown_minutes: number;
  open: number;
  last_triggered_at: string | null;
}

export interface AlertChannelStatus {
  kind: string;
  label: string;
  configured: boolean;
  target: string;
  hint: string;
}

export interface AlertEventItem {
  id: number;
  kind: string;
  domain: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  payload: Record<string, unknown>;
  triggered_at: string;
  resolved_at: string | null;
  delivered_at: string | null;
  delivery_error: string | null;
  delivery_attempts: number;
  next_retry_at: string | null;
  open: boolean;
}

export interface DigestStatus {
  enabled: boolean;
  days: number;
  recipients: string[];
  smtp_configured: boolean;
  jmap_configured: boolean;
  email_configured: boolean;
  transport: "smtp" | "jmap" | null;
  last_sent_at: string | null;
}

export interface AlertsPayload {
  enabled: boolean;
  rules: AlertRuleItem[];
  kinds: AlertKindSpec[];
  channels: AlertChannelStatus[];
  events: AlertEventItem[];
  unresolved: number;
  last_run: string | null;
}

export interface AlertRunResult {
  summary: {
    created: number;
    resolved: number;
    delivered: number;
    failed: number;
    notified: number;
  };
  alerts: AlertsPayload;
}

export interface AlertTestResult {
  ok: boolean;
  results: { channel: string; ok: boolean; error: string | null }[];
  error?: string;
}


export interface ShareLinkItem {
  id: number;
  domain: string | null;
  days: number;
  include_sources: boolean;
  created_at: string | null;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  uses: number;
  revoked: boolean;
}

export interface CreatedShareLink extends ShareLinkItem {
  token: string;
  url: string;
}

export interface PublicShareView {
  scope: {
    domain: string | null;
    days: number;
    include_sources: boolean;
    expires_at: string;
  };
  dashboard: Dashboard;
}
