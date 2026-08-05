use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use hickory_proto::rr::RecordType;

use crate::config::{Profile, Resolver};
use crate::types::{CheckResult, Msg, MonitorEvent, PropagationRow, TraceHop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Propagation,
    Audit,
    Trace,
    Monitor,
    Analysis,
}

impl Tab {
    pub const ALL: [Tab; 5] =
        [Tab::Propagation, Tab::Audit, Tab::Trace, Tab::Monitor, Tab::Analysis];
    pub fn title(&self) -> &'static str {
        match self {
            Tab::Propagation => "Propagation",
            Tab::Audit => "Audit",
            Tab::Trace => "Trace",
            Tab::Monitor => "Monitor",
            Tab::Analysis => "Analysis",
        }
    }
    pub fn index(&self) -> usize {
        Tab::ALL.iter().position(|t| t == self).unwrap()
    }
}

/// What main should do after a key press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    RunTab(Tab),
    StartMonitor,
    RunAnalysis,
    DomainChanged,
    /// Resolver profile switched — propagation data is stale.
    ProfileChanged,
}

pub const RTYPES: [RecordType; 6] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::TXT,
    RecordType::NS,
];

pub struct App {
    pub domain: String,
    pub input_mode: bool,
    pub input_buf: String,
    pub profiles: Vec<Profile>,
    pub profile_idx: usize,
    pub picker_open: bool,
    pub picker_idx: usize,
    pub tab: Tab,
    pub rtype: RecordType,
    pub prop_rows: Vec<PropagationRow>,
    pub auth_answer: Vec<String>,
    pub auth_ns: Vec<String>,
    pub audit: Vec<CheckResult>,
    pub trace: Vec<TraceHop>,
    pub monitor_log: Vec<MonitorEvent>,
    pub monitor_snapshot: HashMap<String, (Vec<String>, Option<u32>)>,
    pub monitor_started: bool,
    pub status: String,
    pub loading: bool,
    /// Resolver count of the in-flight propagation run (for the counter).
    pub prop_expected: usize,
    /// Frame counter, advanced once per event-loop iteration (spinner).
    pub tick: u64,
    /// Rows to skip in the current tab body (Up/Down keys).
    pub scroll: u16,
    pub help_open: bool,
    /// Byte index into `input_buf` for the domain-input cursor.
    pub input_cursor: usize,
}

impl App {
    pub fn new(domain: String, monitor_log: Vec<MonitorEvent>, profiles: Vec<Profile>) -> Self {
        App {
            domain,
            input_mode: false,
            input_buf: String::new(),
            profiles,
            profile_idx: 0,
            picker_open: false,
            picker_idx: 0,
            tab: Tab::Propagation,
            rtype: RecordType::A,
            prop_rows: vec![],
            auth_answer: vec![],
            auth_ns: vec![],
            audit: vec![],
            trace: vec![],
            monitor_log,
            monitor_snapshot: HashMap::new(),
            monitor_started: false,
            status: String::new(),
            loading: false,
            prop_expected: 0,
            tick: 0,
            scroll: 0,
            help_open: false,
            input_cursor: 0,
        }
    }

    pub fn active_profile(&self) -> &Profile {
        &self.profiles[self.profile_idx.min(self.profiles.len().saturating_sub(1))]
    }

    pub fn active_resolvers(&self) -> Vec<Resolver> {
        self.active_profile().resolvers.clone()
    }

    /// Set active profile by name (case-insensitive). Returns false if unknown.
    pub fn set_profile(&mut self, name: &str) -> bool {
        match self.profiles.iter().position(|p| p.name.eq_ignore_ascii_case(name)) {
            Some(i) => {
                self.profile_idx = i;
                true
            }
            None => false,
        }
    }

    fn cycle_rtype(&mut self) {
        let i = RTYPES.iter().position(|t| *t == self.rtype).unwrap_or(0);
        self.rtype = RTYPES[(i + 1) % RTYPES.len()];
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.help_open {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => self.help_open = false,
                _ => {}
            }
            return Action::None;
        }

        if self.picker_open {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.picker_idx =
                        (self.picker_idx + self.profiles.len() - 1) % self.profiles.len();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.picker_idx = (self.picker_idx + 1) % self.profiles.len();
                }
                KeyCode::Enter => {
                    self.picker_open = false;
                    if self.picker_idx != self.profile_idx {
                        self.profile_idx = self.picker_idx;
                        return Action::ProfileChanged;
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => self.picker_open = false,
                _ => {}
            }
            return Action::None;
        }

        if self.input_mode {
            match key.code {
                KeyCode::Enter => {
                    let val = self.input_buf.trim().to_string();
                    self.input_mode = false;
                    self.input_buf.clear();
                    if !val.is_empty() {
                        self.domain = val;
                        self.scroll = 0;
                        return Action::DomainChanged;
                    }
                    return Action::None;
                }
                KeyCode::Esc => {
                    self.input_mode = false;
                    self.input_buf.clear();
                    return Action::None;
                }
                KeyCode::Backspace => {
                    // cursor clamped to len: index into buf may trail a cleared buffer
                    if self.input_cursor > 0 && self.input_cursor <= self.input_buf.len() {
                        self.input_cursor -= 1;
                        self.input_buf.remove(self.input_cursor);
                    }
                    return Action::None;
                }
                KeyCode::Delete => {
                    if self.input_cursor < self.input_buf.len() {
                        self.input_buf.remove(self.input_cursor);
                    }
                    return Action::None;
                }
                KeyCode::Left => {
                    self.input_cursor = self.input_cursor.saturating_sub(1);
                    return Action::None;
                }
                KeyCode::Right => {
                    if self.input_cursor < self.input_buf.len() {
                        self.input_cursor += 1;
                    }
                    return Action::None;
                }
                KeyCode::Home => {
                    self.input_cursor = 0;
                    return Action::None;
                }
                KeyCode::End => {
                    self.input_cursor = self.input_buf.len();
                    return Action::None;
                }
                KeyCode::Char(c) => {
                    let idx = self.input_cursor.min(self.input_buf.len());
                    self.input_buf.insert(idx, c);
                    self.input_cursor = idx + 1;
                    return Action::None;
                }
                _ => return Action::None,
            }
        }

        match key.code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Char('d') => {
                self.input_mode = true;
                self.input_buf = self.domain.clone();
                self.input_cursor = self.input_buf.len();
                Action::None
            }
            KeyCode::Tab | KeyCode::Right => {
                self.scroll = 0;
                let next = (self.tab.index() + 1) % Tab::ALL.len();
                self.tab = Tab::ALL[next];
                self.tab_action()
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.scroll = 0;
                let prev = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.tab = Tab::ALL[prev];
                self.tab_action()
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.scroll = 0;
                let idx = c as usize - '1' as usize;
                self.tab = Tab::ALL[idx];
                self.tab_action()
            }
            KeyCode::Char('r') => self.tab_action(),
            KeyCode::Char('?') => {
                self.help_open = true;
                Action::None
            }
            KeyCode::Up => {
                self.scroll = self.scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Down => {
                self.scroll = self.scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Char('p') => {
                self.profile_idx = (self.profile_idx + 1) % self.profiles.len();
                Action::ProfileChanged
            }
            KeyCode::Char('P') => {
                self.picker_open = true;
                self.picker_idx = self.profile_idx;
                Action::None
            }
            KeyCode::Char('t') => {
                self.cycle_rtype();
                if self.tab == Tab::Propagation {
                    Action::RunTab(Tab::Propagation)
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    /// Action to (re)run whatever the current tab needs.
    fn tab_action(&mut self) -> Action {
        match self.tab {
            Tab::Monitor => {
                if self.monitor_started {
                    Action::None
                } else {
                    self.monitor_started = true;
                    Action::StartMonitor
                }
            }
            Tab::Analysis => {
                self.loading = true;
                Action::RunAnalysis
            }
            t => {
                self.loading = true;
                Action::RunTab(t)
            }
        }
    }

    pub fn handle_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Propagation(rows) => {
                self.prop_rows = rows;
                self.loading = false;
            }
            Msg::PropStart(n) => {
                self.prop_rows.clear();
                self.prop_expected = n;
            }
            Msg::PropRow(row) => self.prop_rows.push(row),
            Msg::AuthAnswer(a) => self.auth_answer = a,
            Msg::AuthNs(ns) => self.auth_ns = ns,
            Msg::Audit(r) => {
                self.audit = r;
                self.loading = false;
            }
            Msg::Trace(hops) => {
                self.trace = hops;
                self.loading = false;
            }
            Msg::TraceHopArrived(hop) => {
                self.trace.push(hop);
            }
            Msg::Monitor(ev) => self.monitor_log.insert(0, ev),
            Msg::MonitorSnapshot { rtype, answers, ttl } => {
                self.monitor_snapshot.insert(rtype, (answers, ttl));
            }
            Msg::Error(e) => {
                self.status = format!("error: {e}");
                self.loading = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn profiles() -> Vec<Profile> {
        ["all", "global", "privacy"]
            .iter()
            .map(|n| Profile { name: n.to_string(), resolvers: vec![] })
            .collect()
    }

    fn app() -> App {
        App::new("example.com".into(), vec![], profiles())
    }

    #[test]
    fn q_quits() {
        assert_eq!(app().handle_key(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn tab_switches_and_runs() {
        let mut a = app();
        let act = a.handle_key(key(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Audit);
        assert_eq!(act, Action::RunTab(Tab::Audit));
    }

    #[test]
    fn number_selects_tab() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('3')));
        assert_eq!(a.tab, Tab::Trace);
    }

    #[test]
    fn t_cycles_rtype_and_reruns_on_propagation() {
        let mut a = app();
        let act = a.handle_key(key(KeyCode::Char('t')));
        assert_eq!(a.rtype, RecordType::AAAA);
        assert_eq!(act, Action::RunTab(Tab::Propagation));
    }

    #[test]
    fn d_enters_input_mode_then_enter_changes_domain() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('d')));
        assert!(a.input_mode);
        a.input_buf.clear();
        for c in "new.com".chars() {
            a.handle_key(key(KeyCode::Char(c)));
        }
        let act = a.handle_key(key(KeyCode::Enter));
        assert_eq!(a.domain, "new.com");
        assert_eq!(act, Action::DomainChanged);
        assert!(!a.input_mode);
    }

    #[test]
    fn esc_cancels_input() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('d')));
        a.handle_key(key(KeyCode::Esc));
        assert!(!a.input_mode);
        assert_eq!(a.domain, "example.com");
    }

    #[test]
    fn monitor_starts_once() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('4')));
        assert_eq!(a.tab, Tab::Monitor);
        assert!(a.monitor_started);
        // second visit does not restart
        a.handle_key(key(KeyCode::Char('1')));
        let act = a.handle_key(key(KeyCode::Char('4')));
        assert_eq!(act, Action::None);
    }

    #[test]
    fn p_cycles_profile() {
        let mut a = app();
        let act = a.handle_key(key(KeyCode::Char('p')));
        assert_eq!(a.profile_idx, 1);
        assert_eq!(act, Action::ProfileChanged);
        a.handle_key(key(KeyCode::Char('p')));
        a.handle_key(key(KeyCode::Char('p')));
        assert_eq!(a.profile_idx, 0);
    }

    #[test]
    fn picker_selects_profile() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('P')));
        assert!(a.picker_open);
        a.handle_key(key(KeyCode::Down));
        let act = a.handle_key(key(KeyCode::Enter));
        assert!(!a.picker_open);
        assert_eq!(a.profile_idx, 1);
        assert_eq!(act, Action::ProfileChanged);
    }

    #[test]
    fn picker_esc_keeps_profile() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('P')));
        a.handle_key(key(KeyCode::Down));
        let act = a.handle_key(key(KeyCode::Esc));
        assert!(!a.picker_open);
        assert_eq!(a.profile_idx, 0);
        assert_eq!(act, Action::None);
    }

    #[test]
    fn set_profile_by_name() {
        let mut a = app();
        assert!(a.set_profile("PRIVACY"));
        assert_eq!(a.profile_idx, 2);
        assert!(!a.set_profile("nope"));
    }

    #[test]
    fn arrows_scroll_and_tab_switch_resets() {
        let mut a = app();
        a.handle_key(key(KeyCode::Down));
        a.handle_key(key(KeyCode::Down));
        assert_eq!(a.scroll, 2);
        a.handle_key(key(KeyCode::Up));
        assert_eq!(a.scroll, 1);
        a.handle_key(key(KeyCode::Tab));
        assert_eq!(a.scroll, 0);
    }

    #[test]
    fn scroll_saturates_at_zero() {
        let mut a = app();
        a.handle_key(key(KeyCode::Up));
        assert_eq!(a.scroll, 0);
    }

    #[test]
    fn question_mark_toggles_help() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('?')));
        assert!(a.help_open);
        // keys other than close keys are swallowed while help is open
        let act = a.handle_key(key(KeyCode::Char('r')));
        assert_eq!(act, Action::None);
        assert!(a.help_open);
        a.handle_key(key(KeyCode::Esc));
        assert!(!a.help_open);
    }

    #[test]
    fn input_cursor_moves_and_inserts() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('d'))); // buf = "example.com", cursor at end
        assert_eq!(a.input_cursor, a.input_buf.len());
        a.handle_key(key(KeyCode::Home));
        assert_eq!(a.input_cursor, 0);
        a.handle_key(key(KeyCode::Char('x')));
        assert!(a.input_buf.starts_with('x'));
        assert_eq!(a.input_cursor, 1);
        a.handle_key(key(KeyCode::End));
        a.handle_key(key(KeyCode::Backspace));
        a.handle_key(key(KeyCode::Left));
        let before = a.input_cursor;
        a.handle_key(key(KeyCode::Right));
        assert_eq!(a.input_cursor, before + 1);
    }

    #[test]
    fn prop_start_resets_rows_and_sets_expected() {
        let mut a = app();
        a.prop_rows.push(crate::types::PropagationRow {
            resolver: "old".into(), ip: "1.1.1.1".parse().unwrap(),
            answers: vec![], ttl: None, latency_ms: None, error: None, matches_auth: None,
        });
        a.handle_msg(Msg::PropStart(16));
        assert!(a.prop_rows.is_empty());
        assert_eq!(a.prop_expected, 16);
        let row = crate::types::PropagationRow {
            resolver: "r1".into(), ip: "1.1.1.1".parse().unwrap(),
            answers: vec!["1.2.3.4".into()], ttl: Some(60), latency_ms: Some(5),
            error: None, matches_auth: Some(true),
        };
        a.handle_msg(Msg::PropRow(row));
        assert_eq!(a.prop_rows.len(), 1);
    }

    #[test]
    fn handle_msg_updates_state() {
        let mut a = app();
        a.loading = true;
        a.handle_msg(Msg::Audit(vec![CheckResult {
            name: "x".into(),
            severity: crate::types::Severity::Ok,
            detail: "d".into(),
        }]));
        assert_eq!(a.audit.len(), 1);
        assert!(!a.loading);
    }
}
