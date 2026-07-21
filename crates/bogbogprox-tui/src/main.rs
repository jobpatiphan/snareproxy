//! `bogbogprox-tui` — terminal UI over the daemon's REST API (§5.1).

mod httpclient;
mod sse;

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use bogbogprox_core::model::{Flow, FlowEvent, FlowSummary, Source};

#[derive(Parser)]
#[command(name = "bogbogprox-tui", version, about = "BogBogProx terminal UI")]
struct Cli {
    /// Full API base URL. Overrides --host/--port and supports HTTPS.
    #[arg(long)]
    api: Option<String>,
    /// API host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// API port.
    #[arg(long, default_value_t = 9000)]
    port: u16,
    /// Team-mode session token (or set BOGBOGPROX_TOKEN).
    #[arg(long)]
    token: Option<String>,
}

struct App {
    client: httpclient::ApiClient,
    /// Newest-first, mirroring the REST list order.
    flows: Vec<FlowSummary>,
    state: ListState,
    /// Selection tracked by flow id so live inserts don't shift the cursor.
    selected_id: Option<i64>,
    detail: Option<Flow>,
    detail_for: Option<i64>,
    status: String,
    /// Last AI activity + when it arrived (shown briefly in the header).
    activity: Option<(String, Instant)>,
    /// Request-intercept on/off (mirrored from the daemon).
    intercept_on: bool,
    /// Held items awaiting a decision: (id, is_response, label).
    held: std::collections::VecDeque<(u64, bool, String)>,
    events: Receiver<FlowEvent>,
    last_refresh: Instant,
}

impl App {
    fn new(client: httpclient::ApiClient) -> Self {
        let events = sse::subscribe(client.clone());
        Self {
            client,
            flows: Vec::new(),
            state: ListState::default(),
            selected_id: None,
            detail: None,
            detail_for: None,
            status: "connecting…".into(),
            activity: None,
            intercept_on: false,
            held: std::collections::VecDeque::new(),
            events,
            last_refresh: Instant::now() - Duration::from_secs(10),
        }
    }

    /// Full reload from REST — the initial snapshot and a periodic self-heal in
    /// case the SSE stream drops.
    fn refresh(&mut self) {
        if let Ok(flows) = self
            .client
            .get_json::<Vec<FlowSummary>>("/api/v1/flows?limit=500")
        {
            self.flows = flows;
            self.status = format!("{} flows", self.flows.len());
            self.resolve_selection();
            self.ensure_detail();
        }
        self.last_refresh = Instant::now();
    }

    /// Drain everything the live stream has delivered since last tick.
    fn pump_events(&mut self) {
        let mut touched_selected = false;
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                FlowEvent::FlowNew { summary } => {
                    if !self.flows.iter().any(|f| f.id == summary.id) {
                        self.flows.insert(0, summary); // newest first
                    }
                }
                FlowEvent::FlowUpdate { summary } => {
                    if Some(summary.id) == self.selected_id {
                        touched_selected = true;
                    }
                    if let Some(slot) = self.flows.iter_mut().find(|f| f.id == summary.id) {
                        *slot = summary;
                    } else {
                        self.flows.insert(0, summary);
                    }
                }
                FlowEvent::Activity { activity } => {
                    let label = if activity.tool == "connect" {
                        format!("🤖 {} connected", activity.agent)
                    } else {
                        format!(
                            "🤖 {} → {} · {}",
                            activity.agent, activity.tool, activity.detail
                        )
                    };
                    self.activity = Some((label, Instant::now()));
                }
                // Intercept is driven from the Web UI for now; surface a hint in
                // the TUI status line but don't handle it here.
                FlowEvent::InterceptPaused { id, request } => {
                    let label = format!("{} {}{}", request.method, request.host, request.path);
                    self.held.push_back((id, false, label));
                }
                FlowEvent::InterceptRespPaused { id, response } => {
                    self.held
                        .push_back((id, true, format!("response {}", response.status)));
                }
                FlowEvent::InterceptResolved { id, .. } => {
                    self.held.retain(|(hid, _, _)| *hid != id);
                }
                FlowEvent::InterceptState { on, .. } => self.intercept_on = on,
                FlowEvent::Finding { finding } => {
                    self.activity = Some((format!("⚠ {}", finding.title), Instant::now()));
                }
                FlowEvent::WsMessage { msg } => {
                    let arrow = if msg.direction == "send" {
                        "▲"
                    } else {
                        "▼"
                    };
                    self.activity = Some((
                        format!("🔌 {arrow} {} {}", msg.host, msg.kind),
                        Instant::now(),
                    ));
                }
                FlowEvent::Presence { operator, status } => {
                    self.activity = Some((format!("👤 {operator} {status}"), Instant::now()));
                }
                FlowEvent::ConfigChanged { .. } => {}
            }
        }
        self.status = format!("{} flows", self.flows.len());
        self.resolve_selection();
        // Reload detail if the selected flow just gained its response.
        if touched_selected {
            self.detail_for = None;
        }
        self.ensure_detail();
    }

    fn selected_index(&self) -> Option<usize> {
        let id = self.selected_id?;
        self.flows.iter().position(|f| f.id == id)
    }

    /// Keep `selected_id`, `state`, and the flow list consistent.
    fn resolve_selection(&mut self) {
        if self.flows.is_empty() {
            self.selected_id = None;
            self.state.select(None);
            return;
        }
        // Default to the newest flow if nothing valid is selected.
        if self.selected_index().is_none() {
            self.selected_id = Some(self.flows[0].id);
        }
        self.state.select(self.selected_index());
    }

    /// Fetch the full flow for the selection, but only when it changed.
    fn ensure_detail(&mut self) {
        if self.selected_id == self.detail_for {
            return;
        }
        self.detail = match self.selected_id {
            Some(id) => self
                .client
                .get_json::<Flow>(&format!("/api/v1/flows/{id}"))
                .ok(),
            None => None,
        };
        self.detail_for = self.selected_id;
    }

    fn move_by(&mut self, delta: isize) {
        let Some(cur) = self.selected_index() else {
            return;
        };
        let next = (cur as isize + delta).clamp(0, self.flows.len() as isize - 1) as usize;
        self.selected_id = Some(self.flows[next].id);
        self.state.select(Some(next));
        self.ensure_detail();
    }

    fn select_index(&mut self, i: usize) {
        if let Some(f) = self.flows.get(i) {
            self.selected_id = Some(f.id);
            self.state.select(Some(i));
            self.ensure_detail();
        }
    }

    /// Resend the selected request through the repeater (§5.1 `r`). The new flow
    /// also arrives via the live stream, but we jump to it immediately.
    fn resend(&mut self) {
        let Some(id) = self.selected_id else { return };
        match self
            .client
            .post_json::<Flow>(&format!("/api/v1/repeater/from/{id}"))
        {
            Ok(flow) => {
                let new_id = flow.id;
                if !self.flows.iter().any(|f| f.id == new_id) {
                    // insert a placeholder summary; the stream will flesh it out
                    self.flows.insert(0, summary_from(&flow));
                }
                self.selected_id = Some(new_id);
                self.detail = Some(flow);
                self.detail_for = Some(new_id);
                self.resolve_selection();
                self.activity = Some((format!("↻ resent → #{new_id}"), Instant::now()));
            }
            Err(e) => self.activity = Some((format!("resend failed: {e}"), Instant::now())),
        }
    }
}

impl App {
    /// Toggle request intercept (state syncs back via the SSE event).
    fn toggle_intercept(&mut self) {
        let body = format!("{{\"on\":{}}}", !self.intercept_on);
        let _ = self.client.post_body("/api/v1/intercept", &body);
    }

    /// Forward (as-is) or drop the oldest held item. Editing is Web-only.
    fn resolve_held(&mut self, drop: bool) {
        let Some((id, is_resp, _)) = self.held.front().cloned() else {
            return;
        };
        let path = match (is_resp, drop) {
            (false, false) => format!("/api/v1/intercept/{id}/forward"),
            (false, true) => format!("/api/v1/intercept/{id}/drop"),
            (true, false) => format!("/api/v1/intercept/{id}/forward-response"),
            (true, true) => format!("/api/v1/intercept/{id}/drop-response"),
        };
        if self.client.post(&path).is_ok() {
            self.held.retain(|(hid, _, _)| *hid != id);
        }
    }
}

fn summary_from(flow: &Flow) -> FlowSummary {
    FlowSummary {
        id: flow.id,
        ts: flow.ts,
        source: flow.source,
        method: flow.request.method.clone(),
        scheme: flow.request.scheme.clone(),
        host: flow.request.host.clone(),
        port: flow.request.port,
        path: flow.request.path.clone(),
        status: flow.response.as_ref().map(|r| r.status),
        mime: flow
            .response
            .as_ref()
            .and_then(|r| r.mime().map(String::from)),
        resp_size: flow.response.as_ref().map(|r| r.body.len() as u64),
        duration_ms: flow.duration_ms,
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let api = cli
        .api
        .unwrap_or_else(|| format!("http://{}:{}", cli.host, cli.port));
    let token = cli
        .token
        .or_else(|| std::env::var("BOGBOGPROX_TOKEN").ok())
        .filter(|token| !token.is_empty());
    let client = httpclient::ApiClient::new(api, token)?;
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(client);
    app.refresh(); // initial snapshot
    let res = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn run<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        app.pump_events();
        // Cheap periodic self-heal in case the live stream dropped silently.
        if app.last_refresh.elapsed() > Duration::from_secs(15) {
            app.refresh();
        }
        terminal.draw(|f| draw(f, app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('j') | KeyCode::Down => app.move_by(1),
                    KeyCode::Char('k') | KeyCode::Up => app.move_by(-1),
                    KeyCode::Char('g') => app.select_index(0),
                    KeyCode::Char('G') => {
                        if !app.flows.is_empty() {
                            app.select_index(app.flows.len() - 1);
                        }
                    }
                    KeyCode::Char('r') => app.resend(),
                    KeyCode::Char('R') => app.refresh(),
                    KeyCode::Char('i') => app.toggle_intercept(),
                    KeyCode::Char('f') => app.resolve_held(false),
                    KeyCode::Char('d') => app.resolve_held(true),
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    let mut title_spans = vec![
        Span::styled(
            " 🪤 BogBogProx ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(app.status.clone(), Style::default().fg(Color::Cyan)),
    ];
    if app.intercept_on {
        title_spans.push(Span::raw("  "));
        title_spans.push(Span::styled(
            " ⏸ INTERCEPT ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ));
    }
    // A held request/response takes priority in the header.
    if let Some((id, _, label)) = app.held.front() {
        title_spans.push(Span::raw("  "));
        title_spans.push(Span::styled(
            format!("HELD #{id} {label} — f=forward d=drop"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
        if app.held.len() > 1 {
            title_spans.push(Span::styled(
                format!("  (+{} more)", app.held.len() - 1),
                Style::default().fg(Color::DarkGray),
            ));
        }
    } else if let Some((label, at)) = &app.activity {
        // Otherwise show the latest AI activity for a few seconds.
        if at.elapsed() < Duration::from_secs(8) {
            title_spans.push(Span::raw("   "));
            title_spans.push(Span::styled(
                label.clone(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
        }
    }
    f.render_widget(Paragraph::new(Line::from(title_spans)), chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(chunks[1]);

    let items: Vec<ListItem> = app
        .flows
        .iter()
        .map(|fl| {
            let status = fl
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "···".into());
            let color = match fl.status {
                Some(s) if s < 300 => Color::Green,
                Some(s) if s < 400 => Color::Cyan,
                Some(s) if s < 500 => Color::Yellow,
                Some(_) => Color::Red,
                None => Color::DarkGray,
            };
            let tag = if fl.source == Source::Repeater {
                "↻"
            } else {
                " "
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{tag} "), Style::default().fg(Color::Yellow)),
                Span::styled(format!("{status:>3} "), Style::default().fg(color)),
                Span::styled(
                    format!("{:<5} ", fl.method),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw(format!("{}{}", fl.host, fl.path)),
            ]))
        })
        .collect();

    let mut list_state = app.state.clone();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" flows "))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, body[0], &mut list_state);

    f.render_widget(detail_widget(app), body[1]);

    let help = Line::from(Span::styled(
        " j/k move · g/G top/bottom · r resend · i intercept · f/d forward/drop · R reload · q quit ",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(help), chunks[2]);
}

fn detail_widget<'a>(app: &'a App) -> Paragraph<'a> {
    let mut lines: Vec<Line> = Vec::new();
    if let Some(flow) = &app.detail {
        let req = &flow.request;
        lines.push(Line::from(Span::styled(
            format!("{} {}", req.method, req.url()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for (k, v) in req.headers.iter().take(20) {
            lines.push(Line::from(vec![
                Span::styled(format!("{k}: "), Style::default().fg(Color::Blue)),
                Span::raw(v.clone()),
            ]));
        }
        if !req.body.is_empty() {
            lines.push(Line::from(""));
            lines.push(body_preview("request body", &req.body));
        }
        if req.body_truncated {
            lines.push(Line::from(Span::styled(
                "[capture truncated; wire body was complete]",
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(""));
        if let Some(resp) = &flow.response {
            lines.push(Line::from(Span::styled(
                format!("← {} ({} bytes)", resp.status, resp.body.len()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            for (k, v) in resp.headers.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("{k}: "), Style::default().fg(Color::Blue)),
                    Span::raw(v.clone()),
                ]));
            }
            if !resp.body.is_empty() {
                lines.push(Line::from(""));
                lines.push(body_preview("response body", &resp.body));
            }
            if resp.body_truncated {
                lines.push(Line::from(Span::styled(
                    "[capture truncated; wire body was complete]",
                    Style::default().fg(Color::Yellow),
                )));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "(awaiting response…)",
                Style::default().fg(Color::DarkGray),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "select a flow — or start browsing through the proxy",
            Style::default().fg(Color::DarkGray),
        )));
    }
    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" detail "))
        .wrap(Wrap { trim: false })
}

fn body_preview<'a>(label: &str, body: &[u8]) -> Line<'a> {
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.chars().take(2000).collect();
    Line::from(vec![
        Span::styled(format!("[{label}] "), Style::default().fg(Color::DarkGray)),
        Span::raw(snippet),
    ])
}
