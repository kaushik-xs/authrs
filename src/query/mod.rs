//! RSQL query support: parse the `q`/`sort` query params into a validated,
//! parameterized Postgres `WHERE`/`ORDER BY` fragment for list endpoints.
//!
//! `rsql` is the (dialect-independent) parser ported from the Architect SDK; `filter`
//! is the authrs-specific builder that maps parsed fields onto an explicit per-endpoint
//! allowlist and rejects unknown or sensitive fields.

pub mod filter;
pub mod rsql;

pub use filter::{build, BuiltQuery, FieldMap, FieldSpec, FieldType};
pub use rsql::{parse_rsql, parse_sort, FilterNode, SortSpec};

/// Parse the optional `q` (RSQL filter) and `sort` params from a list request into the
/// pieces the repos consume. Returns `(filter, sort)`; a missing/blank `q` yields `None`.
pub fn parse_list_params(
    q: Option<&str>,
    sort: Option<&str>,
) -> Result<(Option<FilterNode>, Vec<SortSpec>), crate::error::AppError> {
    let filter = match q {
        Some(s) if !s.trim().is_empty() => Some(parse_rsql(s)?),
        _ => None,
    };
    let sort = sort.map(parse_sort).unwrap_or_default();
    Ok((filter, sort))
}

/// Clamp a requested `limit` to the documented maximum (1000), defaulting to `default`
/// when absent. `offset` defaults to 0.
pub fn clamp_pagination(limit: Option<u32>, offset: Option<u32>, default: u32) -> (u32, u32) {
    let limit = limit.unwrap_or(default).min(1000);
    let offset = offset.unwrap_or(0);
    (limit, offset)
}
