use std::error::Error;

use clap::Parser;

use crate::{
    git::{RemoteOpts, Repo},
    term::{
        node::prelude::*,
        render::{Render, TermRenderer},
        setup_progress_bar,
    },
};

#[derive(Parser, Default)]
#[clap(about = "Pull changes")]
pub struct Opts {
    #[clap(short, long, help = "Show detailed output")]
    details: bool,

    #[clap(short, long, help = "Enable (experimental) rebase mode")]
    rebase: bool,

    #[clap(help = "Branch to pull from")]
    branch: Option<String>,
}

pub fn run(repo: Repo, opts: Opts) -> Result<(), Box<dyn Error>> {
    {
        let mut head = repo.head()?;
        let head_branch = head.shorthand()?.to_string();
        let branch_name = opts.branch.as_deref().unwrap_or(&head_branch);

        let branch = repo.find_branch(branch_name)?;
        let upstream = branch.upstream()?;
        let remote = upstream.remote_name()?;

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = setup_progress_bar(rx);

        let mut remote = repo.find_remote(remote)?;
        remote.fetch(RemoteOpts::default().with_progress(tx), branch_name)?;

        let _ = handle.join();

        let oid = branch.upstream()?.target()?;
        let upstream = repo.find_annotated_commit(oid)?;
        let (analysis, _) = repo.merge_analysis(&upstream)?;

        if analysis.is_up_to_date() {
            let mut ui = TermRenderer::default();
            return Ok(ui.renderln(&message_with_icon(Icon::Check, "up to date"))?);
        } else if analysis.is_fast_forward() {
            let target = head.set_target(oid, "fast-forward")?;
            repo.checkout_tree(&target.find_tree()?, true)?;
        } else {
            return Err("unable to fast-forward (rebase not implemented)".into());
        }
    }

    super::status::run(gix::open(repo.path())?, super::status::Opts::default())
}
