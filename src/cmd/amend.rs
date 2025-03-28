use std::error::Error;

use clap::Parser;
use gix::ObjectId;
use inquire::ui::{Color, RenderConfig};

use crate::{
    cmd::add::add_callback,
    git::Repo,
    term::{
        self,
        node::prelude::*,
        render::{Render, TermRenderer},
    },
};

#[derive(Parser)]
#[clap(about = "Amend recorded changes to the repository")]
pub struct Opts {
    #[clap(short, long, help = "Add all changes")]
    add_all: bool,

    #[clap(short, long, help = "Amend without prompting")]
    yes: bool,

    #[clap(help = "Commit message")]
    message: Option<String>,
}

pub fn run(repo: Repo, opts: Opts) -> Result<(), Box<dyn Error>> {
    let mut index = repo.index()?;

    if opts.add_all {
        index.add(["."], add_callback)?;
        index.write()?;
    }

    let mut ui = TermRenderer::default();
    let oid = index.write_tree()?;
    let mut head = repo.head()?;
    let tree = repo.find_tree(oid)?;
    let (oid, message) = {
        let commit = head.find_commit()?;

        if !opts.yes {
            ui.renderln(&multi_line!(
                dimmed!(commit.headers_ui()),
                spacer!(),
                text!(commit.message_formatted())
            ))?;

            let mut config = RenderConfig::default_colored();
            config.prompt.fg = Some(Color::LightCyan);

            if !term::confirm("Amend this commit?")? {
                return Ok(());
            }
        }

        let parent = commit.parent()?.ok_or("unable to amend empty commit")?;
        let message = match opts.message {
            Some(message) => message,
            None => commit.message()?.to_string(),
        };
        let oid = repo.create_commit(&tree, &message, Some(&parent))?;

        (oid, message)
    };

    head.set_target(oid, &format!("commit amended: {message}"))?;

    ui.renderln(&continued!(block!(
        text!("Created"),
        spacer!(),
        Node::Attribute(Attribute::CommitShort(ObjectId::try_from(oid.as_bytes())?))
    )))?;

    Ok(())
}
