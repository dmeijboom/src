use std::error::Error;

use clap::Parser;
use colored::Colorize;
use git2::{Config, Repository};

use crate::{
    cmd::add::add_callback,
    git::{commit::Commit, index::Index},
    utils,
};

#[derive(Parser)]
#[clap(about = "Amend recorded changes to the repository")]
pub struct Opts {
    #[clap(short, long, help = "Add all changes")]
    add_all: bool,

    #[clap(help = "Commit message")]
    message: Option<String>,
}

pub fn run(repo: Repository, opts: Opts) -> Result<(), Box<dyn Error>> {
    let mut index = Index::build(&repo)?;

    if opts.add_all {
        index.add(["."].iter(), add_callback)?;
        index.write()?;
    }

    let tree = index.write_tree()?;
    let latest = repo.head()?.peel_to_commit()?;
    let config = Config::open_default()?;

    let message = opts
        .message
        .as_deref()
        .unwrap_or_else(|| latest.message().unwrap_or_default());
    let commit = Commit::build(&config, &repo, tree);
    let oid = commit.create(message, Some(&latest.author()), Some(&latest.parent(0)?))?;

    repo.head()?
        .set_target(oid, &format!("commit: {message}"))?;

    println!("Created {}", utils::short(&oid).yellow());

    Ok(())
}
