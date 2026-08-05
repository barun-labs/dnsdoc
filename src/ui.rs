use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table, Tabs,
};
use ratatui::Frame;

use crate::app::{App, Tab};
use crate::checks::analysis::{analyze_propagation, synthesize};
use crate::checks::propagation::consensus;
use crate::types::{Diagnosis, Severity};

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner_frame(tick: u64) -> char {
    SPINNER[(tick % 10) as usize]
}

/// Skip `scroll` items and attach a scrollbar when content overflows.
fn scrolled_list(f: &mut Frame, area: Rect, items: Vec<ListItem<'static>>, block: Block<'static>, scroll: u16) {
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
    }
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
}

/// Centered popup listing every key binding; key column cyan.
fn draw_help(f: &mut Frame) {
    let area = f.area();
    let w = 46.min(area.width);
    let h = 14.min(area.height);
    let rect = Rect {
        x: area.width.saturating_sub(w) / 2,
        y: area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let items: Vec<ListItem> = [
        ("q", "quit"),
        ("Tab/1-5/←→", "tabs"),
        ("↑↓", "scroll"),
        ("r", "rerun"),
        ("t", "record type"),
        ("d", "domain"),
        ("p/P", "profile"),
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
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(app.input_buf.clone(), Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]))
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

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!(" {}·{} ", i + 1, t.title())))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" dnsdoc — {} · [{}] ", app.domain, app.active_profile().name)),
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
        .constraints([Constraint::Length(banner_h), Constraint::Min(3)])
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

    let (agree, answered) = consensus(&app.prop_rows);
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
                Some(e) => (e.clone(), Style::default().fg(Color::DarkGray)),
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
                Cell::from(r.latency_ms.map(|l| l.to_string()).unwrap_or_default()),
                Cell::from(Line::from(mark)),
            ])
        })
        .collect();

    // same skip + scrollbar math as scrolled_list, applied to the row vec
    let total = rows.len();
    let visible = split[1].height.saturating_sub(2) as usize; // borders
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
    f.render_widget(table, split[1]);
    if total > visible {
        let mut state = ScrollbarState::new(max_off).position(off);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            split[1],
            &mut state,
        );
    }
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
            .map(|(i, h)| {
                let indent = "  ".repeat(i);
                let mut spans = vec![
                    Span::raw(format!("{indent}{} ", h.zone)),
                    Span::styled(format!("@{}", h.server), Style::default().fg(Color::Cyan)),
                ];
                if let Some(ms) = h.latency_ms {
                    spans.push(Span::styled(format!(" {ms}ms"), Style::default().fg(Color::DarkGray)));
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
                ListItem::new(Line::from(spans))
            })
            .collect()
    };
    scrolled_list(
        f,
        area,
        items,
        Block::default().borders(Borders::ALL).title(" Delegation trace "),
        app.scroll,
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
        .map(|(rt, (answers, ttl))| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{rt:<6}"), Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if answers.is_empty() { "(empty)".into() } else { answers.join(", ") }),
                Span::styled(
                    ttl.map(|t| format!("  ttl {t}s")).unwrap_or_default(),
                    Style::default().fg(Color::DarkGray),
                ),
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
                if e.flap {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", e.timestamp), Style::default().fg(Color::DarkGray)),
                        Span::styled(format!("{} {} → {} ↻ round-robin?", e.rtype, e.old.join(","), e.new.join(",")),
                            Style::default().fg(Color::DarkGray)),
                    ]))
                } else {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", e.timestamp), Style::default().fg(Color::DarkGray)),
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
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let text = if app.input_mode {
        format!("domain> {}_ (Enter run · Esc cancel)", app.input_buf)
    } else if !app.status.is_empty() {
        app.status.clone()
    } else {
        "q quit · Tab/1-5 switch · r rerun · t record-type · d domain · p/P profile · ? help".to_string()
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
}
