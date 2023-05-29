use crate::command::Command;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use hasher::Hasher;
use khf::Khf;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::{fmt::Write, str::FromStr};
use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Span, Spans},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use unicode_width::UnicodeWidthStr;

pub struct App<R, H, const N: usize> {
    command: String,
    history: Vec<String>,
    forest: Khf<R, H, N>,
    scroll: u16,
}

impl<R, H, const N: usize> App<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    pub fn new(forest: Khf<R, H, N>) -> Self {
        Self {
            command: " $ ".into(),
            history: Vec::new(),
            forest,
            scroll: 0,
        }
    }

    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.ui(f))?;

            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Backspace => {
                        if self.command.len() > 3 {
                            self.command.pop();
                        }
                    }
                    KeyCode::Enter => {
                        let mut command = self.command.drain(3..).collect::<String>();
                        match Command::from_str(&command)? {
                            Command::Derive(key) => {
                                write!(command, " [{}]", hex::encode(self.forest.derive(key)?))?;
                            }
                            Command::Update(key) => {
                                write!(command, " [{}]", hex::encode(self.forest.update(key)?))?;
                            }
                            Command::Commit => {
                                self.forest.commit();
                            }
                            Command::Clear => {
                                self.history.clear();
                                continue;
                            }
                            Command::Truncate(keys) => {
                                self.forest.truncate(keys);
                            }
                            Command::Invalid => {}
                        }
                        self.history.push(command);
                    }
                    KeyCode::Down => {
                        self.scroll = self.scroll.wrapping_add(1);
                    }
                    KeyCode::Up => {
                        self.scroll = self.scroll.wrapping_sub(1);
                    }
                    KeyCode::Char(c) => match (key.modifiers, c) {
                        (KeyModifiers::CONTROL, 'c') => {
                            return Ok(());
                        }
                        (KeyModifiers::CONTROL, 'u') => {
                            self.command.drain(3..);
                        }
                        (KeyModifiers::CONTROL, 'w') => {
                            if let Some(index) =
                                self.command.trim().chars().rev().position(|c| c == ' ')
                            {
                                let index = self.command.trim().chars().count() - index + 1;
                                if index >= 3 {
                                    self.command.drain(index..);
                                } else {
                                    self.command.drain(3..);
                                }
                            }
                        }
                        (KeyModifiers::CONTROL, 'j') => {
                            self.scroll += 1;
                        }
                        (KeyModifiers::CONTROL, 'k') => {
                            self.scroll = if self.scroll == 0 { 0 } else { self.scroll - 1 };
                        }
                        (_, _) => {
                            self.command.push(c);
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    fn ui<B: Backend>(&self, f: &mut Frame<B>) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(f.size());
        self.draw_input_ui(f, chunks[0]);
        self.draw_forest_ui(f, chunks[1]);
    }

    fn draw_forest_ui<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let padding = self
            .forest
            .to_string()
            .split('\n')
            .map(|line| line.chars().count())
            .max()
            .unwrap();

        let string = self
            .forest
            .to_string()
            .split('\n')
            .map(|line| line.to_owned() + &" ".repeat(padding - line.chars().count()))
            .collect::<Vec<_>>()
            .join("\n");

        let forest = Paragraph::new(string)
            .style(Style::default())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" Forest "),
            )
            .alignment(Alignment::Center)
            .scroll((self.scroll, 0));

        f.render_widget(forest, area);
    }

    fn draw_input_ui<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
            .split(area);
        self.draw_command_ui(f, chunks[0]);
        self.draw_history_ui(f, chunks[1]);
    }

    fn draw_command_ui<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let command = Paragraph::new(self.command.as_ref())
            .style(Style::default())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" Command "),
            );
        f.render_widget(command, area);

        let cursor = (area.x + self.command.width() as u16 + 1, area.y + 1);
        f.set_cursor(cursor.0, cursor.1);
    }

    fn draw_history_ui<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let history: Vec<ListItem> = self
            .history
            .iter()
            .rev()
            .map(|m| {
                let content = vec![Spans::from(Span::raw(format!(" $ {}", m)))];
                ListItem::new(content)
            })
            .collect();
        let history = List::new(history).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" History "),
        );
        f.render_widget(history, area);
    }
}
