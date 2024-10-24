use std::{
    error::Error,
    io::{self, ErrorKind, Write},
};

use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use colored::Colorize;
use git2::{Commit, Repository};
use pager::Pager;

use crate::utils;

#[derive(Parser)]
#[clap(about = "Show commit logs")]
pub struct Opts {
    #[clap(long, short, help = "Show logs in one line without metadata")]
    short: bool,

    #[clap(long, help = "Disable the pager")]
    no_pager: bool,
}

fn is_signed(commit: &Commit) -> bool {
    commit
        .header_field_bytes("gpgsig")
        .map(|sig| !sig.is_empty())
        .unwrap_or(false)
}

fn _run(repo: Repository, opts: Opts) -> Result<(), Box<dyn Error>> {
    let mut stdout = io::stdout();
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;

    for oid in revwalk {
        let id = oid?;
        let commit = repo.find_commit(id)?;
        let created_at = DateTime::from_timestamp(commit.time().seconds(), 0)
            .map(|dt| dt.naive_local())
            .map(|dt| Local.from_utc_datetime(&dt))
            .unwrap_or_default();
        let signed = if is_signed(&commit) {
            "⚿ ".green()
        } else if opts.short {
            "  ".white()
        } else {
            "".white()
        };

        if let Err(e) = writeln!(
            stdout,
            "{signed}{} {}",
            utils::short(&id).yellow(),
            commit.message().unwrap_or_default().trim()
        ) {
            if e.kind() == ErrorKind::BrokenPipe {
                return Ok(());
            }
        }

        if !opts.short {
            let _ = write!(
                stdout,
                "{}\n{}\n\n",
                format!("Date: {}", created_at.format("%Y-%m-%d %H:%M")).bright_black(),
                format!("Author: {}", commit.author()).bright_black(),
            );
        }
    }

    Ok(())
}

pub fn run(repo: Repository, opts: Opts) -> Result<(), Box<dyn Error>> {
    if opts.no_pager {
        _run(repo, opts)
    } else {
        colored::control::set_override(true);
        Pager::with_default_pager("less -R").setup();
        _run(repo, opts)
    }
}
