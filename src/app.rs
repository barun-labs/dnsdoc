use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use hickory_proto::rr::RecordType;

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
    pub tab: Tab,
    pub rtype: RecordType,
    pub prop_rows: Vec<PropagationRow>,
    pub auth_answer: Vec<String>,
    pub audit: Vec<CheckResult>,
    pub trace: Vec<TraceHop>,
    pub monitor_log: Vec<MonitorEvent>,
    pub monitor_snapshot: HashMap<String, (Vec<String>, Option<u32>)>,
    pub monitor_started: bool,
    pub status: String,
    pub loading: bool,
}

impl App {
    pub fn new(domain: String, monitor_log: Vec<MonitorEvent>) -> Self {
        App {
            domain,
            input_mode: false,
            input_buf: String::new(),
            tab: Tab::Propagation,
            rtype: RecordType::A,
            prop_rows: vec![],
            auth_answer: vec![],
            audit: vec![],
            trace: vec![],
            monitor_log,
            monitor_snapshot: HashMap::new(),
            monitor_started: false,
            status: String::new(),
            loading: false,
        }
    }

    fn cycle_rtype(&mut self) {
        let i = RTYPES.iter().position(|t| *t == self.rtype).unwrap_or(0);
        self.rtype = RTYPES[(i + 1) % RTYPES.len()];
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if self.input_mode {
            match key.code {
                KeyCode::Enter => {
                    let val = self.input_buf.trim().to_string();
                    self.input_mode = false;
                    self.input_buf.clear();
                    if !val.is_empty() {
                        self.domain = val;
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
                    self.input_buf.pop();
                    return Action::None;
                }
                KeyCode::Char(c) => {
                    self.input_buf.push(c);
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
                Action::None
            }
            KeyCode::Tab | KeyCode::Right => {
                let next = (self.tab.index() + 1) % Tab::ALL.len();
                self.tab = Tab::ALL[next];
                self.tab_action()
            }
            KeyCode::BackTab | KeyCode::Left => {
                let prev = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.tab = Tab::ALL[prev];
                self.tab_action()
            }
            KeyCode::Char(c @ '1'..='5') => {
                let idx = c as usize - '1' as usize;
                self.tab = Tab::ALL[idx];
                self.tab_action()
            }
            KeyCode::Char('r') => self.tab_action(),
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
            Msg::AuthAnswer(a) => self.auth_answer = a,
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

    fn app() -> App {
        App::new("example.com".into(), vec![])
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
