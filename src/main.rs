use std::path::PathBuf;

use clap::Parser;
use colored::Colorize;
use git2::Repository;

mod callbacks;
mod cmd;
mod named;
mod utils;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = ".")]
    dir: PathBuf,

    #[clap(subcommand)]
    cmd: Option<Cmd>,

    #[clap(help = "Branch name to checkout")]
    branch: Option<String>,
}

#[derive(Parser)]
enum Cmd {
    Add(cmd::add::Opts),
    Commit(cmd::commit::Opts),
    Push(cmd::push::Opts),
    Fetch(cmd::fetch::Opts),
    List(cmd::list::Opts),
    Diff(cmd::diff::Opts),
}

fn main() {
    let opts = Opts::parse();
    let app = || {
        let repo = Repository::open(opts.dir)?;

        match opts.cmd {
            Some(Cmd::Add(opts)) => cmd::add::run(repo, opts),
            Some(Cmd::Commit(opts)) => cmd::commit::run(repo, opts),
            Some(Cmd::Push(opts)) => cmd::push::run(repo, opts),
            Some(Cmd::Fetch(opts)) => cmd::fetch::run(repo, opts),
            Some(Cmd::List(opts)) => cmd::list::run(repo, opts),
            Some(Cmd::Diff(opts)) => cmd::diff::run(repo, opts),
            None => match opts.branch {
                Some(branch) => cmd::checkout::run(repo, branch),
                None => cmd::status::run(repo),
            },
        }
    };

    if let Err(e) = app() {
        eprintln!("{}", format!("⚠️ {e}").red());
    }
}
