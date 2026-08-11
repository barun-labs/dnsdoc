use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, Tabs,
};
use ratatui::Frame;

use crate::app::{App, Tab};
use crate::checks::analysis::{analyze_propagation, synthesize};
use crate::checks::monitor::sparkline;
use crate::checks::propagation::consensus;
use crate::types::{CheckResult, Diagnosis, PropagationRow, Severity};

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner_frame(tick: u64) -> char {
    SPINNER[(tick % 10) as usize]
}

fn latency_color(ms: u128) -> Color {
    if ms < 50 {
        Color::Green
    } else if ms < 200 {
        Color::Yellow
    } else {
        Color::Red
    }
}

pub fn relative_age(ts: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return ts.to_string();
    };
    let secs = (now - t.with_timezone(&chrono::Utc)).num_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

/// Skip `scroll` items and attach a scrollbar when content overflows.
fn scrolled_list(f: &mut Frame, area: Rect, items: Vec<ListItem<'static>>, block: Block<'static>, scroll: u16, noun: &str) {
    let total = items.len();
    let visible = area.height.saturating_sub(2) as usize; // borders
    let max_off = total.saturating_sub(visible);
    let off = (scroll as usize).min(max_off);
    let shown: Vec<ListItem> = items.into_iter().skip(off).collect();
    f.render_widget(List::new(shown).block(block), area);
    if total > visible {
        let mut state = ScrollbarState::new(max_off).position(off);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area,
            &mut state,
        );
    } else {
        render_list_fill(f, area, total, total.min(visible) as u16, noun);
    }
}

/// Fill dead space below a short list with a centered end-of-results marker.
fn render_list_fill(f: &mut Frame, area: Rect, total: usize, shown: u16, noun: &str) {
    let used = 2 + shown; // borders only, no header row
    let gap = area.height.saturating_sub(used);
    if gap < 4 {
        return;
    }
    let line = Line::from(Span::styled(
        format!("── {shown}/{total} {noun} · end of results ──"),
        Style::default().fg(Color::DarkGray),
    ));
    let rect = Rect {
        x: area.x,
        y: area.y + used + gap.saturating_sub(1) / 2,
        width: area.width,
        height: 1,
    };
    f.render_widget(Paragraph::new(line).alignment(Alignment::Center), rect);
}

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Min(1),    // body
            Constraint::Length(1), // status
        ])
        .split(f.area());

    draw_tabs(f, app, chunks[0]);
    match app.tab {
        Tab::Propagation => draw_propagation(f, app, chunks[1]),
        Tab::Audit => draw_audit(f, app, chunks[1]),
        Tab::Trace => draw_trace(f, app, chunks[1]),
        Tab::Dnssec => draw_dnssec(f, app, chunks[1]),
        Tab::Mail => draw_mail(f, app, chunks[1]),
        Tab::Sweep => draw_sweep(f, app, chunks[1]),
        Tab::Monitor => draw_monitor(f, app, chunks[1]),
        Tab::Analysis => draw_analysis(f, app, chunks[1]),
    }
    draw_status(f, app, chunks[2]);
    if app.picker_open {
        draw_profile_picker(f, app);
    }
    if app.input_mode {
        draw_domain_input(f, app);
    }
    if app.help_open {
        draw_help(f);
    }
    if app.add_open {
        draw_add_resolver(f, app);
    }
    if app.reverse_open || !app.reverse_result.is_empty() {
        draw_reverse(f, app);
    }
}

/// Add-resolver popup: one-line "name ip" input while open.
fn draw_add_resolver(f: &mut Frame, app: &App) {
    let area = f.area();
    let w = 60.min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(3) / 2,
        width: w,
        height: 3,
    };
    f.render_widget(Clear, rect);
    let cursor = app.add_cursor.min(app.add_buf.len());
    let before = &app.add_buf[..cursor];
    let rest = &app.add_buf[cursor..];
    let mut spans = vec![Span::styled(before.to_string(), Style::default().add_modifier(Modifier::BOLD))];
    if rest.is_empty() {
        spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
    } else {
        spans.push(Span::styled(
            rest[..rest.chars().next().unwrap().len_utf8()].to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            rest[rest.chars().next().unwrap().len_utf8()..].to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Add resolver — name ip · Enter save · Esc cancel "),
        ),
        rect,
    );
}

/// Reverse-lookup popup: input box while open, result list once populated.
/// Shown when `reverse_open` OR when a result exists (small results panel).
fn draw_reverse(f: &mut Frame, app: &App) {
    let area = f.area();
    let w = 64.min(area.width);
    let results: Vec<ListItem> = app
        .reverse_result
        .iter()
        .map(|l| ListItem::new(l.clone()))
        .collect();
    let n = (results.len() as u16).min(12);
    let total = (if app.reverse_open { 3 + 1 + n } else { n }).min(area.height).max(1);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(total) / 2,
        width: w,
        height: total,
    };
    f.render_widget(Clear, rect);
    if app.reverse_open {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(rect);
        f.render_widget(
            Paragraph::new(app.reverse_buf.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan))
                        .title(" Reverse — IP + Enter look up · Esc close "),
                ),
            split[0],
        );
        f.render_widget(
            List::new(results).block(Block::default().borders(Borders::ALL)),
            split[1],
        );
    } else {
        f.render_widget(
            List::new(results)
                .block(Block::default().borders(Borders::ALL).title(" Reverse — v to look up another ")),
            rect,
        );
    }
}

/// Centered popup listing every key binding; key column cyan.
fn draw_help(f: &mut Frame) {
    let area = f.area();
    let w = 46.min(area.width);
    let h = 18.min(area.height);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let mut items: Vec<ListItem> = [
        ("q", "quit"),
        ("Tab/1-8/←→", "tabs"),
        ("↑↓", "scroll"),
        ("r", "rerun"),
        ("t", "record type"),
        ("d", "domain"),
        ("p/P", "profile"),
        ("e", "export report"),
        ("v", "reverse lookup"),
        ("a", "add resolver"),
        ("?", "help"),
    ]
    .iter()
    .map(|(k, v)| {
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {k:<10} "), Style::default().fg(Color::Cyan)),
            Span::raw(*v),
        ]))
    })
    .collect();
    items.push(ListItem::new(Line::from("")));
    items.push(ListItem::new(Line::from(Span::styled(
        format!(" v{} · {}", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_REPOSITORY")),
        Style::default().fg(Color::DarkGray),
    ))));
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(" Keys — Esc/?/q close ")),
        rect,
    );
}

fn draw_domain_input(f: &mut Frame, app: &App) {
    let area = f.area();
    let w = 60.min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(3) / 2,
        width: w,
        height: 3,
    };
    f.render_widget(Clear, rect);
    let cursor = app.input_cursor.min(app.input_buf.len());
    let before = &app.input_buf[..cursor];
    let rest = &app.input_buf[cursor..];
    let mut spans = vec![Span::styled(before.to_string(), Style::default().add_modifier(Modifier::BOLD))];
    if rest.is_empty() {
        spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
    } else {
        spans.push(Span::styled(
            rest[..rest.chars().next().unwrap().len_utf8()].to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            rest[rest.chars().next().unwrap().len_utf8()..].to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Domain — Enter run · Esc cancel "),
        ),
        rect,
    );
}

/// One-line summary of the authoritative NS set, essential troubleshooting context.
fn ns_line(app: &App) -> Line<'static> {
    let text = if app.auth_ns.is_empty() {
        "NS: (not resolved yet)".to_string()
    } else {
        format!("NS: {}", app.auth_ns.join(" · "))
    };
    Line::from(Span::styled(text, Style::default().fg(Color::Cyan)))
}

fn draw_profile_picker(f: &mut Frame, app: &App) {
    let area = f.area();
    let w = 40.min(area.width);
    let h = (app.profiles.len() as u16 + 2).min(area.height);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let marker = if i == app.profile_idx { "●" } else { " " };
            let line = format!("{marker} {} ({} resolvers)", p.name, p.resolvers.len());
            let style = if i == app.picker_idx {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Resolver profile — Enter select · Esc close "),
        ),
        rect,
    );
}

fn sev_color(sev: Severity) -> Color {
    match sev {
        Severity::Ok => Color::Green,
        Severity::Warn => Color::Yellow,
        Severity::Err => Color::Red,
    }
}

/// Render a diagnosis as a headline line plus indented "based on" evidence.
fn diagnosis_items(d: &Diagnosis) -> Vec<ListItem<'static>> {
    let (tag, _) = sev_style(d.severity);
    let mut items = vec![ListItem::new(Line::from(vec![
        Span::styled(
            format!("{tag} "),
            Style::default().fg(sev_color(d.severity)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(d.headline.clone(), Style::default().add_modifier(Modifier::BOLD)),
    ]))];
    for e in &d.evidence {
        items.push(ListItem::new(Line::from(vec![
            Span::styled("    based on: ", Style::default().fg(Color::DarkGray)),
            Span::raw(e.clone()),
        ])));
    }
    items
}

/// Problem-count badges for tab titles: `✗n` red / `!n` yellow, nothing when clean.
fn tab_badge(tab: Tab, app: &App) -> Vec<Span<'static>> {
    let mut spans = vec![];
    match tab {
        Tab::Propagation => {
            let n = app.prop_rows.iter().filter(|r| r.matches_auth == Some(false)).count();
            if n > 0 {
                spans.push(Span::styled(format!("✗{n} "), Style::default().fg(Color::Red)));
            }
        }
        Tab::Audit => {
            let e = app.audit.iter().filter(|c| c.severity == Severity::Err).count();
            let w = app.audit.iter().filter(|c| c.severity == Severity::Warn).count();
            if e > 0 {
                spans.push(Span::styled(format!("✗{e} "), Style::default().fg(Color::Red)));
            }
            if w > 0 {
                spans.push(Span::styled(format!("!{w} "), Style::default().fg(Color::Yellow)));
            }
        }
        Tab::Trace => {
            let broken = app.trace.iter().any(|h| {
                h.error.is_some()
                    || h.note.as_deref().is_some_and(|n| n.contains("LAME"))
                    || h.dnssec.as_deref().is_some_and(|d| d.contains("BROKEN"))
            });
            if broken {
                spans.push(Span::styled("✗ ", Style::default().fg(Color::Red)));
            }
        }
        _ => {}
    }
    spans
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut spans = vec![Span::raw(format!(" {}·{} ", i + 1, t.title()))];
            spans.extend(tab_badge(*t, app));
            Line::from(spans)
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " dnsdoc v{} — {} · [{}] ",
                    env!("CARGO_PKG_VERSION"),
                    app.domain,
                    app.active_profile().name
                )),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, area);
}

fn sev_style(sev: Severity) -> (&'static str, Style) {
    match sev {
        Severity::Ok => ("OK  ", Style::default().fg(Color::Green)),
        Severity::Warn => ("WARN", Style::default().fg(Color::Yellow)),
        Severity::Err => ("ERR ", Style::default().fg(Color::Red)),
    }
}

fn draw_propagation(f: &mut Frame, app: &App, area: Rect) {
    // Split: reasoned diagnosis banner on top, resolver table below.
    let rows_present = !app.prop_rows.is_empty();
    let diag = analyze_propagation(&format!("{:?}", app.rtype), &app.auth_answer, &app.prop_rows, chrono::Utc::now());
    let banner_h = if rows_present { (diag.evidence.len() as u16 + 4).min(10) } else { 3 };
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(banner_h), Constraint::Length(1), Constraint::Min(3)])
        .split(area);

    if rows_present {
        let mut items = vec![ListItem::new(ns_line(app))];
        items.extend(diagnosis_items(&diag));
        f.render_widget(
            List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Diagnosis ")),
            split[0],
        );
    } else {
        f.render_widget(
            Paragraph::new(if app.loading {
                format!(
                    "{} querying resolvers… {}/{}",
                    spinner_frame(app.tick),
                    app.prop_rows.len(),
                    app.prop_expected
                )
            } else {
                "press 'r' to run".to_string()
            })
            .block(Block::default().borders(Borders::ALL).title(" Diagnosis ")),
            split[0],
        );
    }

    // Consensus gauge: agree/answered ratio, green full, yellow partial, red none.
    let (agree, answered) = consensus(&app.prop_rows);
    if rows_present {
        let ratio = agree as f64 / answered.max(1) as f64;
        let color = if agree == answered && answered > 0 {
            Color::Green
        } else if agree == 0 {
            Color::Red
        } else {
            Color::Yellow
        };
        f.render_widget(
            Gauge::default()
                .ratio(ratio)
                .gauge_style(Style::default().fg(color))
                .label(format!("{agree}/{answered} agree")),
            split[1],
        );
    }
    let auth = if app.auth_answer.is_empty() {
        "unknown".to_string()
    } else {
        app.auth_answer.join(", ")
    };
    let mut title = format!(" {:?} — {agree}/{answered} match | auth: {auth} ", app.rtype);
    if app.loading {
        title.push_str(&format!(
            " {} {}/{} answered ",
            spinner_frame(app.tick),
            app.prop_rows.len(),
            app.prop_expected
        ));
    }

    let header = Row::new(["Resolver", "Answer", "TTL", "ms", "✓"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .prop_rows
        .iter()
        .map(|r| {
            let (answer, style) = match &r.error {
                // Timeout is a transport-level miss (dim); rcode errors like
                // REFUSED/SERVFAIL are real server answers — show them red.
                Some(e) if e == "timeout" => (e.clone(), Style::default().fg(Color::DarkGray)),
                Some(e) => (e.clone(), Style::default().fg(Color::Red)),
                None => (
                    if r.answers.is_empty() { "(empty)".into() } else { r.answers.join(", ") },
                    Style::default(),
                ),
            };
            let mark = match r.matches_auth {
                Some(true) => Span::styled("✓", Style::default().fg(Color::Green)),
                Some(false) => Span::styled("✗", Style::default().fg(Color::Red)),
                None => Span::raw("·"),
            };
            Row::new(vec![
                Cell::from(format!("{} ({})", r.resolver, r.ip)),
                Cell::from(answer).style(style),
                Cell::from(r.ttl.map(|t| t.to_string()).unwrap_or_default()),
                Cell::from(r.latency_ms.map(|l| l.to_string()).unwrap_or_default())
                    .style(match r.latency_ms {
                        Some(l) => Style::default().fg(latency_color(l)),
                        None => Style::default(),
                    }),
                Cell::from(Line::from(mark)),
            ])
        })
        .collect();

    // same skip + scrollbar math as scrolled_list, applied to the row vec
    let total = rows.len();
    let visible = split[2].height.saturating_sub(2) as usize; // borders
    let max_off = total.saturating_sub(visible);
    let off = (app.scroll as usize).min(max_off);
    let rows: Vec<Row> = rows.into_iter().skip(off).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Min(20),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(3),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, split[2]);
    if total > visible {
        let mut state = ScrollbarState::new(max_off).position(off);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            split[2],
            &mut state,
        );
    } else {
        // dead space below a short table: latency tiers + summary
        render_propagation_fill(f, split[2], &app.prop_rows, total as u16);
    }
}

/// Fill dead space below a short resolver table with latency-tier bars and a
/// summary; a one-line footer when space is tight, full block when tall.
fn render_propagation_fill(f: &mut Frame, area: Rect, rows: &[PropagationRow], rows_shown: u16) {
    let used = 2 + 1 + rows_shown; // borders + header row
    let gap = area.height.saturating_sub(used);
    if gap < 4 {
        return;
    }
    let (agree, answered) = consensus(rows);
    let footer = format!("── {agree}/{answered} resolvers · end of results ──");
    let lines: Vec<Line> = if gap < 11 {
        vec![Line::from(Span::styled(footer, Style::default().fg(Color::DarkGray)))]
    } else {
        // One pass: bucket latencies, count timeouts, collect timed values.
        let mut buckets = [0usize; 6]; // <20, 20-49, 50-99, 100-199, 200-499, 500+
        let mut timeouts = 0;
        let mut lats = Vec::new();
        for r in rows {
            if r.error.is_some() {
                timeouts += 1;
                continue;
            }
            let Some(ms) = r.latency_ms else { continue }; // no latency data: skip
            lats.push(ms);
            let idx = if ms < 20 {
                0
            } else if ms < 50 {
                1
            } else if ms < 100 {
                2
            } else if ms < 200 {
                3
            } else if ms < 500 {
                4
            } else {
                5
            };
            buckets[idx] += 1;
        }
        let bar_cap = area.width.saturating_sub(24) as usize;
        let labels = ["<20ms", "20-49", "50-99", "100-199", "200-499", "500+"];
        let lows = [0u128, 20, 50, 100, 200, 500];
        let mut lines = Vec::new();
        for (i, label) in labels.iter().enumerate() {
            let bar = "█".repeat(buckets[i].min(bar_cap));
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<9}"), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{bar} {}", buckets[i]), Style::default().fg(latency_color(lows[i]))),
            ]));
        }
        lines.push(Line::from(vec![
            // Covers timeouts AND real-but-negative answers (REFUSED, SERVFAIL,
            // ...) — anything that stopped the row from having a latency at
            // all. Labeled "error", not "timeout": a REFUSED is a real
            // response, not a stall, and this app's own screenshots show
            // resolvers that REFUSE far more often than they time out.
            Span::styled("error    ".to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} {}", "█".repeat(timeouts.min(bar_cap)), timeouts),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::default());
        lats.sort_unstable();
        let stats = if lats.is_empty() {
            "no latency data".to_string()
        } else {
            let median = if lats.len() % 2 == 0 {
                lats[lats.len() / 2 - 1] // lower-middle, no averaging
            } else {
                lats[lats.len() / 2]
            };
            format!("min {}ms · median {}ms · max {}ms", lats[0], median, lats[lats.len() - 1])
        };
        lines.push(Line::from(Span::styled(
            format!("{stats} · {timeouts} errors · {agree}/{answered} match auth"),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(footer, Style::default().fg(Color::DarkGray))));
        lines
    };
    let n = lines.len() as u16;
    let rect = Rect {
        x: area.x,
        y: area.y + used + gap.saturating_sub(n) / 2,
        width: area.width,
        height: n,
    };
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), rect);
}

fn draw_audit(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.audit.is_empty() {
        vec![ListItem::new(if app.loading {
            format!("{} running checks…", spinner_frame(app.tick))
        } else {
            "press 'r' to run audit".to_string()
        })]
    } else {
        app.audit
            .iter()
            .map(|c| {
                let (tag, style) = sev_style(c.severity);
                ListItem::new(Line::from(vec![
                    Span::styled(tag, style.add_modifier(Modifier::BOLD)),
                    Span::raw(format!("  {:<16} ", c.name)),
                    Span::raw(c.detail.clone()),
                ]))
            })
            .collect()
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(" Audit "),
        app.scroll,
        "checks",
    );
}

/// DNSSEC checks grouped under RRSIG expiry / validation matrix / chain detail
/// sub-headers, ordered by the checks' name prefixes.
fn draw_dnssec(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.dnssec.is_empty() {
        vec![ListItem::new(if app.loading {
            format!("{} running dnssec checks…", spinner_frame(app.tick))
        } else {
            "press 'r' to run dnssec checks".to_string()
        })]
    } else {
        let groups: [(&str, fn(&CheckResult) -> bool); 3] = [
            ("RRSIG expiry", |c| c.name.starts_with("RRSIG")),
            (
                "Validation matrix",
                |c| c.name == "DNSSEC validation" || c.name.starts_with("validate"),
            ),
            ("Chain detail", |c| c.name.starts_with("chain")),
        ];
        let mut items = Vec::new();
        for (header, pred) in groups {
            let selected: Vec<&CheckResult> = app.dnssec.iter().filter(|c| pred(c)).collect();
            if selected.is_empty() {
                continue;
            }
            items.push(ListItem::new(Line::from(Span::styled(
                format!("— {header} —"),
                Style::default().add_modifier(Modifier::BOLD),
            ))));
            for c in selected {
                let (tag, style) = sev_style(c.severity);
                items.push(ListItem::new(Line::from(vec![
                    Span::styled(tag, style.add_modifier(Modifier::BOLD)),
                    Span::raw(format!("  {:<16} ", c.name)),
                    Span::raw(c.detail.clone()),
                ])));
            }
        }
        items
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(" DNSSEC "),
        app.scroll,
        "records",
    );
}

fn draw_mail(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.mail.is_empty() {
        vec![ListItem::new(if app.loading {
            format!("{} running mail checks…", spinner_frame(app.tick))
        } else {
            "press 'r' to run mail checks".to_string()
        })]
    } else {
        app.mail
            .iter()
            .map(|c| {
                let (tag, style) = sev_style(c.severity);
                ListItem::new(Line::from(vec![
                    Span::styled(tag, style.add_modifier(Modifier::BOLD)),
                    Span::raw(format!("  {:<16} ", c.name)),
                    Span::raw(c.detail.clone()),
                ]))
            })
            .collect()
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(" Mail "),
        app.scroll,
        "checks",
    );
}

/// Placeholder until the Sweep task fills in real probing.
fn draw_sweep(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.sweep_rows.is_empty() {
        vec![ListItem::new(if app.loading {
            format!("{} sweeping…", spinner_frame(app.tick))
        } else {
            "press 'r' to sweep common records".to_string()
        })]
    } else {
        app.sweep_rows
            .iter()
            .map(|r| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{} ", r.name)),
                    Span::styled(format!("{}  ", r.rtype), Style::default().fg(Color::Cyan)),
                    Span::raw(if r.answers.is_empty() {
                        "(empty)".into()
                    } else {
                        r.answers.join(", ")
                    }),
                ]))
            })
            .collect()
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Sweep — {} hits ", app.sweep_rows.len())),
        app.scroll,
        "hits",
    );
}

fn draw_trace(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.trace.is_empty() {
        vec![ListItem::new(if app.loading {
            format!("{} tracing…", spinner_frame(app.tick))
        } else {
            "press 'r' to trace delegation".to_string()
        })]
    } else {
        app.trace
            .iter()
            .enumerate()
            .flat_map(|(i, h)| {
                let indent = if i == 0 {
                    String::new()
                } else {
                    format!("{}└─ ", "   ".repeat(i - 1))
                };
                let mut spans = vec![
                    Span::raw(format!("{indent}{} ", h.zone)),
                    Span::styled(format!("@{}", h.server), Style::default().fg(Color::Cyan)),
                ];
                if let Some(ms) = h.latency_ms {
                    spans.push(Span::styled(format!(" {ms}ms"), Style::default().fg(latency_color(ms))));
                }
                if let Some(n) = &h.note {
                    let color = if n.contains("LAME") { Color::Red } else { Color::White };
                    spans.push(Span::styled(format!("  {n}"), Style::default().fg(color)));
                }
                if let Some(d) = &h.dnssec {
                    let color = if d.contains("BROKEN") { Color::Red }
                        else if d.starts_with("signed") { Color::Green }
                        else { Color::Yellow };
                    spans.push(Span::styled(format!("  [{d}]"), Style::default().fg(color)));
                }
                if let Some(e) = &h.error {
                    spans.push(Span::styled(format!("  ERROR: {e}"), Style::default().fg(Color::Red)));
                }
                // One dim line per referral NS, indented beneath the hop glyph.
                let mut items = vec![ListItem::new(Line::from(spans))];
                let child_indent = if i == 0 {
                    String::new()
                } else {
                    format!("{}   ", "   ".repeat(i - 1))
                };
                for n in &h.ns {
                    items.push(ListItem::new(Line::from(Span::styled(
                        format!("{child_indent}   • {n}"),
                        Style::default().fg(Color::DarkGray),
                    ))));
                }
                items
            })
            .collect()
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(" Delegation trace "),
        app.scroll,
        "hops",
    );
}

fn draw_monitor(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Left: current snapshot per record type
    let mut snap: Vec<ListItem> = app
        .monitor_snapshot
        .iter()
        .map(|(rt, (answers, ttl, received))| {
            let countdown = match ttl {
                Some(t) => {
                    let left = (*t as u64).saturating_sub(received.elapsed().as_secs());
                    format!("  ttl {t}s (~{left}s left)")
                }
                None => String::new(),
            };
            // Latency sparkline: last 60 polls, latest ms value appended.
            let latencies: Vec<u64> = app
                .monitor_latency
                .get(rt)
                .map(|q| q.iter().copied().collect())
                .unwrap_or_default();
            let spark = if latencies.is_empty() {
                String::new()
            } else {
                let latest = *latencies.last().unwrap();
                format!("  {} {latest}ms", sparkline(&latencies))
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{rt:<6}"), Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if answers.is_empty() { "(empty)".into() } else { answers.join(", ") }),
                Span::styled(countdown, Style::default().fg(Color::DarkGray)),
                Span::styled(spark, Style::default().fg(Color::Cyan)),
            ]))
        })
        .collect();
    if snap.is_empty() {
        snap.push(ListItem::new("polling…"));
    }
    f.render_widget(
        List::new(snap).block(Block::default().borders(Borders::ALL).title(" Current ")),
        cols[0],
    );

    // Right: change log (newest first)
    let log: Vec<ListItem> = if app.monitor_log.is_empty() {
        vec![ListItem::new("no changes recorded")]
    } else {
        app.monitor_log
            .iter()
            .map(|e| {
                let age = relative_age(&e.timestamp, chrono::Utc::now());
                if e.flap {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{age} "), Style::default().fg(Color::DarkGray)),
                        Span::styled(format!("{} {} → {} ↻ round-robin?", e.rtype, e.old.join(","), e.new.join(",")),
                            Style::default().fg(Color::DarkGray)),
                    ]))
                } else {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{age} "), Style::default().fg(Color::DarkGray)),
                        Span::styled(format!("{} ", e.rtype), Style::default().fg(Color::Cyan)),
                        Span::styled(e.old.join(","), Style::default().fg(Color::Red)),
                        Span::raw(" → "),
                        Span::styled(e.new.join(","), Style::default().fg(Color::Green)),
                    ]))
                }
            })
            .collect()
    };
    scrolled_list(
        f,
        cols[1],
        log,
        Block::default().borders(Borders::ALL).title(" Change log "),
        app.scroll,
        "events",
    );
}

fn draw_analysis(f: &mut Frame, app: &App, area: Rect) {
    let have_data = !app.prop_rows.is_empty() || !app.audit.is_empty() || !app.trace.is_empty();
    if !have_data {
        f.render_widget(
            Paragraph::new(if app.loading {
                "gathering evidence — running propagation, audit and trace…"
            } else {
                "press 'r' to run all checks and synthesize a diagnosis"
            })
            .block(Block::default().borders(Borders::ALL).title(" Analysis ")),
            area,
        );
        return;
    }

    let prop = if app.prop_rows.is_empty() {
        None
    } else {
        Some(analyze_propagation(
            &format!("{:?}", app.rtype),
            &app.auth_answer,
            &app.prop_rows,
            chrono::Utc::now(),
        ))
    };
    let diagnoses = synthesize(prop.as_ref(), &app.prop_rows, &app.audit, &app.trace);

    let mut items = vec![ListItem::new(ns_line(app)), ListItem::new(Line::from(""))];
    for (i, d) in diagnoses.iter().enumerate() {
        if i > 0 {
            items.push(ListItem::new(Line::from("")));
        }
        items.extend(diagnosis_items(d));
    }
    let title = format!(" Analysis — {} probable finding(s), most severe first ", diagnoses.len());
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(title),
        app.scroll,
        "findings",
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let text = if app.input_mode {
        format!("domain> {}_ (Enter run · Esc cancel)", app.input_buf)
    } else if !app.status.is_empty() {
        app.status.clone()
    } else {
        "q quit · Tab/1-8 switch · r rerun · t record-type · d domain · p/P profile · e export · v reverse · a add resolver · ? help".to_string()
    };
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Gray)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spinner_cycles() {
        let a = spinner_frame(0);
        let b = spinner_frame(1);
        assert_ne!(a, b);
        assert_eq!(spinner_frame(0), spinner_frame(10)); // 10 frames
    }

    #[test]
    fn latency_color_bands() {
        assert_eq!(latency_color(10), Color::Green);
        assert_eq!(latency_color(120), Color::Yellow);
        assert_eq!(latency_color(700), Color::Red);
    }

    /// Row-by-row rendering of a frame buffer, for eyeballing layouts in test output.
    fn buffer_to_string(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn propagation_fill_renders_latency_tiers() {
        let mut app = App::new(
            "example.com".into(),
            vec![],
            vec![crate::config::Profile { name: "default".into(), resolvers: vec![] }],
        );
        app.tab = Tab::Propagation;
        app.prop_rows = vec![
            PropagationRow {
                resolver: "r1".into(), ip: "1.1.1.1".parse().unwrap(),
                answers: vec!["1.2.3.4".into()], ttl: Some(60), latency_ms: Some(5),
                error: None, matches_auth: Some(true),
            },
            PropagationRow {
                resolver: "r2".into(), ip: "1.1.1.2".parse().unwrap(),
                answers: vec!["1.2.3.4".into()], ttl: Some(60), latency_ms: Some(30),
                error: None, matches_auth: Some(true),
            },
            PropagationRow {
                resolver: "r3".into(), ip: "1.1.1.3".parse().unwrap(),
                answers: vec!["1.2.3.4".into()], ttl: Some(60), latency_ms: Some(120),
                error: None, matches_auth: Some(true),
            },
            PropagationRow {
                resolver: "r4".into(), ip: "1.1.1.4".parse().unwrap(),
                answers: vec![], ttl: None, latency_ms: None,
                error: Some("timeout".into()), matches_auth: None,
            },
        ];
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 30)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let rendered = buffer_to_string(terminal.backend().buffer());
        println!("{rendered}");
        assert!(rendered.contains("end of results"));
        assert!(rendered.contains("min 5ms"));
        assert!(rendered.contains("1 errors"));
    }

    #[test]
    fn relative_age_formats() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
        assert_eq!(relative_age("2026-08-05T11:59:30+00:00", now), "30s ago");
        assert_eq!(relative_age("2026-08-05T11:57:00+00:00", now), "3m ago");
        assert_eq!(relative_age("2026-08-05T09:00:00+00:00", now), "3h ago");
        assert_eq!(relative_age("2026-08-01T12:00:00+00:00", now), "4d ago");
        assert_eq!(relative_age("garbage", now), "garbage"); // fall back to raw
    }
}
