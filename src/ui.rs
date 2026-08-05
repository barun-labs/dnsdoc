use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs};
use ratatui::Frame;

use crate::app::{App, Tab};
use crate::checks::propagation::consensus;
use crate::types::Severity;

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
    }
    draw_status(f, app, chunks[2]);
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
                .title(format!(" dns-tester — {} ", app.domain)),
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
    let (agree, answered) = consensus(&app.prop_rows);
    let total = app.prop_rows.len();
    let verdict = if answered == 0 {
        "querying…".to_string()
    } else if agree == answered && answered == total {
        "fully propagated".to_string()
    } else {
        format!("{agree}/{answered} resolvers match authoritative — still propagating")
    };
    let auth = if app.auth_answer.is_empty() {
        "(authoritative unknown)".to_string()
    } else {
        app.auth_answer.join(", ")
    };
    let title = format!(" {:?} — {} | auth: {} ", app.rtype, verdict, auth);

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
    f.render_widget(table, area);
}

fn draw_audit(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.audit.is_empty() {
        vec![ListItem::new(if app.loading { "running checks…" } else { "press 'r' to run audit" })]
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
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Audit "));
    f.render_widget(list, area);
}

fn draw_trace(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = if app.trace.is_empty() {
        vec![ListItem::new(if app.loading { "tracing…" } else { "press 'r' to trace delegation" })]
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
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Delegation trace "));
    f.render_widget(list, area);
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
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", e.timestamp), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{} ", e.rtype), Style::default().fg(Color::Cyan)),
                    Span::styled(e.old.join(","), Style::default().fg(Color::Red)),
                    Span::raw(" → "),
                    Span::styled(e.new.join(","), Style::default().fg(Color::Green)),
                ]))
            })
            .collect()
    };
    f.render_widget(
        List::new(log).block(Block::default().borders(Borders::ALL).title(" Change log ")),
        cols[1],
    );
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let text = if app.input_mode {
        format!("domain> {}_", app.input_buf)
    } else if !app.status.is_empty() {
        app.status.clone()
    } else {
        "q quit · Tab/1-4 switch · r rerun · t record-type · d domain".to_string()
    };
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Gray)),
        area,
    );
}
