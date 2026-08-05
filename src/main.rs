use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use hickory_proto::rr::RecordType;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use dnsdoc::app::{Action, App, Tab};
use dnsdoc::checks;
use dnsdoc::config::Config;
use dnsdoc::types::{self, validate_domain, Msg};
use dnsdoc::ui;

#[tokio::main]
async fn main() -> Result<()> {
    // Args: [domain] [--profile NAME]
    let mut domain = String::new();
    let mut profile_arg: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--profile" || a == "-p" {
            profile_arg = args.next();
        } else if let Ok(d) = validate_domain(&a) {
            domain = d;
        }
    }
    let cfg = Config::load();

    let history = checks::monitor::load_history(&cfg.history_path);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run(&mut terminal, cfg, domain, history, profile_arg).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cfg: Config,
    domain: String,
    history: Vec<types::MonitorEvent>,
    profile_arg: Option<String>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Msg>(256);
    let mut app = App::new(domain, history, cfg.profiles.clone());
    if let Some(name) = profile_arg {
        if !app.set_profile(&name) {
            app.status = format!("unknown profile: {name} (P to list)");
        }
    }

    if app.domain.is_empty() {
        app.input_mode = true;
    } else {
        spawn_all(&app, &cfg, tx.clone());
        app.loading = true;
    }

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Drain any ready messages.
        while let Ok(msg) = rx.try_recv() {
            app.handle_msg(msg);
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press {
                    continue;
                }
                match app.handle_key(key) {
                    Action::Quit => break,
                    Action::None => {}
                    Action::RunTab(tab) => {
                        if !app.domain.is_empty() {
                            app.trace.clear();
                            spawn_tab(&app, &cfg, tab, tx.clone());
                        }
                    }
                    Action::StartMonitor => {
                        if !app.domain.is_empty() {
                            spawn_monitor(&app, &cfg, tx.clone());
                        }
                    }
                    Action::RunAnalysis => {
                        if !app.domain.is_empty() {
                            app.trace.clear();
                            spawn_all(&app, &cfg, tx.clone());
                        }
                    }
                    Action::ProfileChanged => {
                        if !app.domain.is_empty() {
                            app.prop_rows.clear();
                            app.loading = true;
                            spawn_tab(&app, &cfg, Tab::Propagation, tx.clone());
                        }
                        app.status = format!("profile: {}", app.active_profile().name);
                    }
                    Action::DomainChanged => {
                        match validate_domain(&app.domain) {
                            Ok(d) => {
                                app.domain = d;
                                app.status.clear();
                                app.prop_rows.clear();
                                app.audit.clear();
                                app.trace.clear();
                                app.monitor_started = false;
                                app.loading = true;
                                spawn_all(&app, &cfg, tx.clone());
                            }
                            Err(e) => app.status = format!("invalid domain: {e}"),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn spawn_tab(app: &App, cfg: &Config, tab: Tab, tx: mpsc::Sender<Msg>) {
    let domain = app.domain.clone();
    match tab {
        Tab::Propagation => {
            let resolvers = app.active_resolvers();
            let rtype = app.rtype;
            tokio::spawn(checks::propagation::run(domain, rtype, resolvers, tx));
        }
        Tab::Audit => {
            tokio::spawn(checks::audit::run(domain, tx));
        }
        Tab::Trace => {
            tokio::spawn(checks::trace::run(domain, tx));
        }
        Tab::Monitor => spawn_monitor(app, cfg, tx),
        // Analysis fans out to the other checks via Action::RunAnalysis.
        Tab::Analysis => {}
    }
}

/// Fan out propagation, audit and trace so every tab (and Analysis) has data.
fn spawn_all(app: &App, cfg: &Config, tx: mpsc::Sender<Msg>) {
    spawn_tab(app, cfg, Tab::Propagation, tx.clone());
    spawn_tab(app, cfg, Tab::Audit, tx.clone());
    spawn_tab(app, cfg, Tab::Trace, tx);
}

fn spawn_monitor(app: &App, cfg: &Config, tx: mpsc::Sender<Msg>) {
    let domain = app.domain.clone();
    let interval = Duration::from_secs(cfg.poll_interval_secs);
    let history_path = cfg.history_path.clone();
    let rtypes = vec![RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::NS];
    tokio::spawn(checks::monitor::run(domain, rtypes, interval, history_path, tx));
}
