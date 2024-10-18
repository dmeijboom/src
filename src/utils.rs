use std::error::Error;

use git2::{Reference, Repository};

pub fn find_remote_ref<'a>(
    repo: &'a Repository,
    refname: &str,
) -> Result<Reference<'a>, Box<dyn Error>> {
    let remote = repo.branch_upstream_name(refname)?;
    let remote = std::str::from_utf8(&remote)?;

    Ok(repo.find_reference(remote)?)
}
