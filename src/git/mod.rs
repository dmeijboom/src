use chrono::{DateTime, Local, TimeZone};
use git2::{Error, ErrorClass, ErrorCode};

mod config;
mod index;
mod objects;
mod remote;
mod repo;
mod resolve;
mod signer;
mod status;

pub use config::Config;
pub use objects::*;
pub use remote::{ProgressEvent, RemoteOpts, SidebandOp};
pub use repo::{CheckoutError, DiffOpts, Repo};
pub use resolve::Pattern;

pub trait Optional<T> {
    fn optional(self) -> Result<Option<T>, Error>;
}

impl<T> Optional<T> for Result<T, git2::Error> {
    fn optional(self) -> Result<Option<T>, Error> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(e)
                if e.code() == ErrorCode::NotFound
                    && matches!(e.class(), ErrorClass::Config | ErrorClass::Reference) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

pub fn parse_local_time(time: git2::Time) -> DateTime<Local> {
    DateTime::from_timestamp(time.seconds(), 0)
        .map(|dt| dt.naive_local())
        .map(|dt| Local.from_utc_datetime(&dt))
        .unwrap_or_default()
}
