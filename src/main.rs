use std::borrow::Cow;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, ValueHint};
use clap_complete::{generate, Shell};
use colored::Colorize;
use git::Repo;
use git2::{Repository, RepositoryOpenFlags};
use resolve_path::PathResolveExt;
use tracing_subscriber::EnvFilter;

mod cmd;
mod git;
mod graph;
mod progress;
mod rebase;
mod term;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = ".", value_hint = ValueHint::DirPath)]
    dir: PathBuf,

    #[clap(subcommand)]
    cmd: Option<Cmd>,

    #[clap(help = "Branch name to checkout")]
    branch: Option<String>,

    #[arg(long = "generate", value_enum)]
    generator: Option<Shell>,
}

#[derive(Parser)]
enum Cmd {
    Add(cmd::add::Opts),
    Fix(cmd::commit::Opts),
    Feat(cmd::commit::Opts),
    Refactor(cmd::commit::Opts),
    Chore(cmd::commit::Opts),
    Clone(cmd::clone::Opts),
    Commit(cmd::commit::Opts),
    Amend(cmd::amend::Opts),
    Push(cmd::push::Opts),
    Fetch(cmd::fetch::Opts),
    Pull(cmd::pull::Opts),
    Sync(cmd::sync::Opts),
    List(cmd::list::Opts),
    Diff(cmd::diff::Opts),
    Stash(cmd::stash::Opts),
    Unstash(cmd::unstash::Opts),
    Branch(cmd::branch::Opts),
    Checkout(cmd::checkout::Opts),
}

fn open_gix(path: impl AsRef<Path>) -> Result<gix::Repository, gix::open::Error> {
    let base = path.as_ref();
    let resolved = base.resolve();
    let mut dir = resolved.as_ref();

    loop {
        if dir.join(".git").exists() {
            return gix::open(dir);
        }

        let Some(parent) = dir.parent() else {
            return Err(gix::open::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "Git repository not found",
            )));
        };

        dir = parent;
    }
}

fn open_repo(path: impl AsRef<Path>) -> Result<Repo, Box<dyn Error>> {
    let path = path.as_ref();

    Ok(Repo::from(Repository::open_ext(
        path,
        RepositoryOpenFlags::empty(),
        [path],
    )?))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts = Opts::parse();

    if let Some(generator) = opts.generator {
        let mut cmd = Opts::command();
        let bin_name = cmd.get_name().to_string();
        generate(generator, &mut cmd, bin_name, &mut io::stdout());
        return;
    }

    let app = || match opts.cmd {
        Some(Cmd::Clone(opts)) => cmd::clone::run(opts),
        cmd => match cmd {
            Some(cmd) => {
                let repo = open_repo(&opts.dir)?;

                match cmd {
                    Cmd::Add(opts) => cmd::add::run(repo, opts),
                    Cmd::Fix(opts) => cmd::commit::with_prefix("fix", repo, opts),
                    Cmd::Feat(opts) => cmd::commit::with_prefix("feat", repo, opts),
                    Cmd::Chore(opts) => cmd::commit::with_prefix("chore", repo, opts),
                    Cmd::Refactor(opts) => cmd::commit::with_prefix("refactor", repo, opts),
                    Cmd::Commit(opts) => cmd::commit::run(repo, opts),
                    Cmd::Amend(opts) => cmd::amend::run(repo, opts),
                    Cmd::Push(opts) => cmd::push::run(repo, opts),
                    Cmd::Fetch(opts) => cmd::fetch::run(repo, opts),
                    Cmd::Pull(opts) => cmd::pull::run(repo, opts),
                    Cmd::Sync(opts) => cmd::sync::run(repo, opts),
                    Cmd::List(opts) => cmd::list::run(repo, opts),
                    Cmd::Diff(opts) => cmd::diff::run(repo, opts),
                    Cmd::Stash(opts) => cmd::stash::run(repo, opts),
                    Cmd::Unstash(opts) => cmd::unstash::run(repo, opts),
                    Cmd::Branch(opts) => cmd::branch::run(repo, opts),
                    Cmd::Checkout(opts) => cmd::checkout::run(repo, opts),
                    Cmd::Clone(_) => unreachable!(),
                }
            }
            None => match opts.branch {
                Some(branch) => cmd::checkout::run(
                    open_repo(&opts.dir)?,
                    cmd::checkout::Opts::with_branch(branch),
                ),
                None => cmd::status::run(open_gix(opts.dir)?, cmd::status::Opts::default()),
            },
        },
    };

    if let Err(e) = app() {
        eprintln!("{}", format!("⚠️ {e}").red());
    }
}
