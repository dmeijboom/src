use git2::{Repository, StatusEntry, StatusOptions, Statuses};

pub struct Status<'a> {
    statuses: Statuses<'a>,
}

impl<'a> Status<'a> {
    pub fn build(repo: &'a Repository) -> Result<Self, git2::Error> {
        Ok(Self {
            statuses: repo.statuses(Some(
                StatusOptions::new()
                    .include_ignored(false)
                    .include_untracked(true)
                    .recurse_untracked_dirs(true)
                    .exclude_submodules(true),
            ))?,
        })
    }

    pub fn entries(&'a self) -> impl Iterator<Item = Entry<'a>> {
        self.statuses
            .into_iter()
            .filter(|e| e.status() != git2::Status::CURRENT)
            .map(Entry::from)
    }
}

pub enum Change {
    New,
    Type,
    Modified,
    Renamed,
    Deleted,
}

pub enum EntryStatus {
    Unknown,
    WorkTree(Change),
    Index(Change),
}

pub struct Entry<'a> {
    entry: StatusEntry<'a>,
}

impl<'a> Entry<'a> {
    pub fn path(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.entry.path_bytes())
    }

    pub fn status(&self) -> EntryStatus {
        match self.entry.status() {
            s if s.is_wt_new() => EntryStatus::WorkTree(Change::New),
            s if s.is_index_new() => EntryStatus::Index(Change::New),
            s if s.is_wt_modified() => EntryStatus::WorkTree(Change::Modified),
            s if s.is_index_modified() => EntryStatus::Index(Change::Modified),
            s if s.is_wt_renamed() => EntryStatus::WorkTree(Change::Renamed),
            s if s.is_index_renamed() => EntryStatus::Index(Change::Renamed),
            s if s.is_wt_deleted() => EntryStatus::WorkTree(Change::Deleted),
            s if s.is_index_deleted() => EntryStatus::Index(Change::Deleted),
            s if s.is_wt_typechange() => EntryStatus::WorkTree(Change::Type),
            s if s.is_index_typechange() => EntryStatus::Index(Change::Type),
            _ => EntryStatus::Unknown,
        }
    }
}

impl<'a> From<StatusEntry<'a>> for Entry<'a> {
    fn from(entry: StatusEntry<'a>) -> Self {
        Self { entry }
    }
}
