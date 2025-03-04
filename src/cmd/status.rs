use std::error::Error;

use clap::Parser;
use git2::{ErrorCode, RepositoryState};
use minus::Pager;
use tracing::instrument;

use crate::{
    git::{Change, EntryStatus, Repo},
    term::{
        node::prelude::*,
        render::{Render, TermRenderer},
    },
};

#[derive(Parser, Default)]
#[clap(about = "Show status")]
pub struct Opts {
    #[clap(long, help = "Disable the pager")]
    no_pager: bool,
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render_branch(
    ui: &mut impl Render,
    repo: &Repo,
    state: Option<(git2::Oid, git2::Oid)>,
) -> Result<(), Box<dyn Error>> {
    match repo.head() {
        Ok(head) => {
            let mut group = vec![];
            let commit = head.find_commit()?;

            group.push(Node::Attribute(Attribute::from_ref(&head)?));
            group.push(spacer!());

            if let Some(indicators) =
                state.and_then(|state| remote_state_indicators(repo, state).ok().flatten())
            {
                group.push(label!(indicators));
                group.push(spacer!());
            };

            group.push(Node::text_capped(
                commit
                    .message()?
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                75,
            ));

            ui.renderln(&Node::Block(group))?;
            Ok(())
        }
        Err(e) if e.code() == ErrorCode::UnbornBranch => {
            ui.renderln(&Node::Attribute(Attribute::Branch("[no branch]".into())))?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[instrument(skip(repo), ret(Debug))]
fn remote_state_indicators(
    repo: &Repo,
    state: (git2::Oid, git2::Oid),
) -> Result<Option<Node>, Box<dyn Error>> {
    let (local, remote) = state;
    let (ahead, behind) = repo.graph_ahead_behind(local, remote)?;

    Ok(if ahead == 0 && behind == 0 {
        None
    } else if ahead == 0 && behind != 0 {
        Some(block!(
            icon!(ArrowDown).with_status(Status::Error),
            spacer!(),
            text!(behind.to_string())
        ))
    } else if behind == 0 && ahead != 0 {
        Some(block!(
            icon!(ArrowUp).with_status(Status::Success),
            spacer!(),
            text!(ahead.to_string())
        ))
    } else {
        Some(block!(
            icon!(ArrowUp).with_status(Status::Success),
            spacer!(),
            text!(ahead.to_string()),
            spacer!(),
            icon!(ArrowDown).with_status(Status::Error),
            text!(behind.to_string())
        ))
    })
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render_rebase(ui: &mut impl Render, repo: &Repo) -> Result<(), Box<dyn Error>> {
    let rebase = repo.read_rebase()?;
    let mut children = vec![];

    for op in rebase.operations.iter() {
        let id = op.oid.to_string();
        let kind = match op.ty {
            git2::RebaseOperationType::Pick => "pick",
            git2::RebaseOperationType::Reword => "reword",
            git2::RebaseOperationType::Edit => "edit",
            git2::RebaseOperationType::Squash => "squash",
            git2::RebaseOperationType::Fixup => "fixup",
            git2::RebaseOperationType::Exec => "exec",
        };

        children.push(block!(
            spacer!(),
            spacer!(),
            Node::Attribute(Attribute::Operation(kind.into())),
            spacer!(),
            dimmed!(text!(id[..6].to_string())),
            spacer!(),
            Node::text_head_1(op.message.clone())
        ));
    }

    children.push(block!(
        spacer!(),
        spacer!(),
        continued!(text!("Fix conflicts and run 'git rebase --continue'"))
    ));

    ui.renderln(&Node::Group(
        "Rebase".into(),
        Some(rebase.operations.len()),
        Box::new(Node::MultiLine(children)),
    ))?;

    Ok(())
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render_state(ui: &mut impl Render, repo: &Repo) -> Result<(), Box<dyn Error>> {
    match repo.state() {
        RepositoryState::Merge => {
            ui.renderln(&text!("Merge in progress"))?;
            Ok(())
        }
        RepositoryState::Revert | RepositoryState::RevertSequence => {
            ui.renderln(&text!("Revert in progress"))?;
            Ok(())
        }
        RepositoryState::CherryPick | RepositoryState::CherryPickSequence => {
            ui.renderln(&text!("Cherry-pick in progress"))?;
            Ok(())
        }
        RepositoryState::Bisect => todo!(),
        // See: https://github.com/libgit2/libgit2/issues/6332
        RepositoryState::Rebase
        | RepositoryState::RebaseInteractive
        | RepositoryState::RebaseMerge => render_rebase(ui, repo),
        _ => Ok(()),
    }
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render_commits(
    ui: &mut impl Render,
    repo: &Repo,
    local: git2::Oid,
    remote: git2::Oid,
) -> Result<(), Box<dyn Error>> {
    let mut children = vec![];
    let (ahead, behind) = repo.commits_ahead_behind(local, remote)?;
    let groups = [
        ("Unmerged into remote", ahead),
        ("Unpulled from remote", behind),
    ];

    for (name, commits) in groups {
        if commits.is_empty() {
            continue;
        }

        let count = commits.len();
        let mut lines = vec![];

        for commit in commits {
            let id = commit.id().to_string();

            lines.push(block!(
                if commit.is_signed() {
                    icon!(Lock).with_status(Status::Success)
                } else {
                    spacer!()
                },
                spacer!(),
                dimmed!(text!(id[..6].to_string())),
                spacer!(),
                Node::text_head_1(commit.message().unwrap_or_default())
            ));
        }

        children.push(Node::Group(
            name.into(),
            Some(count),
            Box::new(Node::MultiLine(lines)),
        ));
    }

    if children.is_empty() {
        return Ok(());
    }

    Ok(ui.renderln(&Node::MultiLine(children))?)
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render_changes(ui: &mut impl Render, repo: &Repo) -> Result<(), Box<dyn Error>> {
    let mut children = vec![];
    let status = repo.status()?;
    let entries = status.entries().collect::<Vec<_>>();
    let (staged, unstaged): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.is_staged());
    let groups = [("Staged Changes", staged), ("Unstaged Changes", unstaged)];

    for (name, entries) in groups {
        if entries.is_empty() {
            continue;
        }

        let count = entries.len();
        let mut lines = vec![];

        for entry in entries {
            let change = match entry.status() {
                EntryStatus::Unknown => None,
                EntryStatus::WorkTree(change) => Some(change),
                EntryStatus::Index(change) => Some(change),
            };
            let indicator = match change {
                Some(Change::New) => Indicator::New,
                Some(Change::Modified) => Indicator::Modified,
                Some(Change::Renamed) => Indicator::Renamed,
                Some(Change::Deleted) => Indicator::Deleted,
                None | Some(Change::Type) => Indicator::Unknown,
            };

            lines.push(block!(
                spacer!(),
                spacer!(),
                Node::Indicator(indicator),
                spacer!(),
                text!(entry.path()?.to_string())
            ));
        }

        children.push(Node::Group(
            name.into(),
            Some(count),
            Box::new(Node::MultiLine(lines)),
        ));
    }

    if children.is_empty() {
        return Ok(());
    }

    Ok(ui.render(&Node::MultiLine(children))?)
}

#[instrument(skip(repo), ret(Debug))]
fn find_state(repo: &Repo) -> Result<Option<(git2::Oid, git2::Oid)>, Box<dyn Error>> {
    let head = match repo.head() {
        Ok(head) => head,
        Err(e) if e.code() == ErrorCode::UnbornBranch => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    if !head.is_branch() {
        return Ok(None);
    }

    let local = head.target()?;
    let upstream = repo
        .find_upstream_branch(&head)?
        .map(|r| r.target())
        .transpose()?;

    let Some(remote) = upstream else {
        return Ok(None);
    };

    Ok(Some((local, remote)))
}

#[instrument(skip(ui, repo), ret(Debug))]
fn render(mut ui: impl Render, repo: Repo) -> Result<(), Box<dyn Error>> {
    let state = find_state(&repo)?;

    render_branch(&mut ui, &repo, state)?;
    render_state(&mut ui, &repo)?;
    render_changes(&mut ui, &repo)?;

    state
        .map(|(local, remote)| render_commits(&mut ui, &repo, local, remote))
        .transpose()?;

    Ok(())
}

pub fn run(repo: Repo, opts: Opts) -> Result<(), Box<dyn Error>> {
    if opts.no_pager {
        render(TermRenderer::default(), repo)
    } else {
        let mut pager = Pager::new();
        pager.set_prompt("status, q to quit")?;

        render(TermRenderer::new(&mut pager), repo)?;
        minus::page_all(pager)?;

        Ok(())
    }
}
