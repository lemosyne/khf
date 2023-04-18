use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crypter::prelude::*;
use hasher::prelude::*;
use khf::Khf;
use kms::KeyManagementScheme;
use rand::prelude::ThreadRng;
use std::io;
use tui::{backend::CrosstermBackend, Terminal};

mod app;
use app::App;

pub mod command;

#[derive(Parser)]
struct Args {
    /// The fanout list defining the topology of the interactive forest.
    #[arg(short, long, value_delimiter = ',', default_values_t = [2, 2, 2, 2])]
    fanouts: Vec<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let forest = Khf::<Aes256Ctr, ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::setup((
        args.fanouts.clone(),
        ThreadRng::default(),
    ));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = App::new(forest).run(&mut terminal);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}
