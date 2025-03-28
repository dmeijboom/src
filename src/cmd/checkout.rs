use std::error::Error;

use clap::Parser;

use crate::{
    git::{Branch, CheckoutError, Optional, Ref, RemoteOpts, Repo},
    term::{
        node::prelude::*,
        render::{Render, TermRenderer},
        select,
    },
};

#[derive(Parser)]
#[clap(about = "Checkout a branch", alias = "use")]
pub struct Opts {
    #[clap(help = "Branch name")]
    branch: Option<String>,
}

impl Opts {
    pub fn with_branch(branch: String) -> Self {
        Self {
            branch: Some(branch),
        }
    }
}

pub fn try_checkout(repo: &Repo, reference: &Ref<'_>) -> Result<bool, git2::Error> {
    match repo.checkout(reference) {
        Ok(()) => Ok(true),
        Err(CheckoutError::Conflict(_)) => Ok(false),
        Err(CheckoutError::Git(e)) => Err(e),
    }
}

fn branch_names(repo: &Repo) -> Result<Vec<String>, Box<dyn Error>> {
    let branches = repo.branches()?;
    Ok(branches
        .map(|result| {
            result
                .map_err(Into::into)
                .and_then(|branch| branch.name().map(ToOwned::to_owned))
        })
        .collect::<Result<Vec<_>, _>>()?)
}

fn find_remote_branch<'a>(
    repo: &'a Repo,
    branch_name: &str,
) -> Result<Option<Branch<'a>>, Box<dyn Error>> {
    for remote in repo.remotes()? {
        let mut remote = remote?;
        let Some(name) = remote.name()?.map(ToString::to_string) else {
            continue;
        };

        remote.fetch(RemoteOpts::default(), branch_name)?;

        let upstream = format!("{}/{branch_name}", name);
        let branch = repo.find_remote_branch(&upstream)?.into_ref();
        let commit = branch.find_commit()?;

        let mut new_branch = repo.create_branch(branch_name, &commit)?;
        new_branch.set_upstream(&upstream)?;

        return Ok(Some(new_branch));
    }

    Ok(None)
}

pub fn run(mut repo: Repo, opts: Opts) -> Result<(), Box<dyn Error>> {
    let branch_name = match opts.branch {
        Some(branch) => branch,
        None => match select::single(
            &branch_names(&repo)?,
            Some("src list commit {}".to_string()),
        )? {
            Some(branch) => branch,
            None => return Err("No branch selected".into()),
        },
    };

    let branch = match repo.find_branch(&branch_name).optional()? {
        Some(branch) => branch,
        None => match find_remote_branch(&repo, &branch_name) {
            Ok(Some(branch)) => branch,
            Ok(None) => return Err("Branch not found".into()),
            Err(e) => return Err(e),
        },
    };

    if !try_checkout(&repo, &branch.into())? {
        repo.save_stash(&format!("auto stash before checkout to: {branch_name}"))?;

        let mut ui = TermRenderer::default();
        ui.renderln(&message_with_icon(Icon::Check, "Changes stashed"))?;

        let branch = repo.find_branch(&branch_name)?;
        repo.checkout(&branch.into())?;
    }

    super::status::run(gix::open(repo.path())?, super::status::Opts::default())
}
