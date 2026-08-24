//! Turns a parsed RSQL `FilterNode` tree and `SortSpec` list into a parameterized
//! Postgres `WHERE` / `ORDER BY` fragment, validated against a per-endpoint field
//! allowlist (`FieldMap`).
//!
//! Design notes (why this differs from the Architect SDK builder it is ported from):
//!   * authrs has hand-written repos, not a config-driven `ResolvedEntity`, so the set
//!     of filterable fields is declared explicitly per endpoint as a `&[FieldSpec]`.
//!   * SQL identifiers (`column`) come only from these compile-time constants, never
//!     from request input, so injection is structurally impossible. Only *values* are
//!     bound as parameters (always as text; Postgres casts handle typing).
//!   * Sensitive fields are listed but flagged `sensitive: true`; any attempt to filter
//!     or sort on them is rejected with a 422 rather than silently ignored.

use crate::error::AppError;
use crate::query::rsql::{FilterNode, RsqlOp, SortSpec};

/// Coarse type of a filterable column — drives operator validation and the Postgres cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Int,
    Float,
    Bool,
    Uuid,
    Date,
    Timestamp,
    Time,
}

impl FieldType {
    /// Postgres cast applied to the bound text placeholder (e.g. `$3::uuid`), or `None`
    /// for text (no cast needed). Not applied to LIKE-family operators.
    fn cast(self) -> Option<&'static str> {
        match self {
            FieldType::Text => None,
            FieldType::Int => Some("bigint"),
            FieldType::Float => Some("double precision"),
            FieldType::Bool => Some("boolean"),
            FieldType::Uuid => Some("uuid"),
            FieldType::Date => Some("date"),
            FieldType::Timestamp => Some("timestamptz"),
            FieldType::Time => Some("time"),
        }
    }
}

/// One filterable/sortable field: the camelCase name clients use, the trusted SQL column
/// expression it maps to, its type, and whether it is sensitive (never filterable).
pub struct FieldSpec {
    pub api_name: &'static str,
    /// Trusted, already-qualified SQL column expression (e.g. `u.status`, `i.email`).
    pub column: &'static str,
    pub ty: FieldType,
    pub sensitive: bool,
}

/// The allowlist of fields for one endpoint.
pub type FieldMap = [FieldSpec];

fn lookup<'a>(fields: &'a FieldMap, api_name: &str) -> Result<&'a FieldSpec, AppError> {
    let spec = fields
        .iter()
        .find(|f| f.api_name == api_name)
        .ok_or_else(|| AppError::Validation(format!("unknown filter field '{}'", api_name)))?;
    if spec.sensitive {
        return Err(AppError::Validation(format!(
            "field '{}' is not filterable",
            api_name
        )));
    }
    Ok(spec)
}

fn op_valid_for_type(op: &RsqlOp, ty: FieldType) -> bool {
    match ty {
        FieldType::Text => matches!(
            op,
            RsqlOp::Eq
                | RsqlOp::Neq
                | RsqlOp::In
                | RsqlOp::Out
                | RsqlOp::Like
                | RsqlOp::Ilike
                | RsqlOp::Contains
                | RsqlOp::Starts
                | RsqlOp::Ends
                | RsqlOp::Null(_)
        ),
        FieldType::Int | FieldType::Float => matches!(
            op,
            RsqlOp::Eq
                | RsqlOp::Neq
                | RsqlOp::Gt
                | RsqlOp::Ge
                | RsqlOp::Lt
                | RsqlOp::Le
                | RsqlOp::Between
                | RsqlOp::In
                | RsqlOp::Out
                | RsqlOp::Null(_)
        ),
        FieldType::Bool => matches!(op, RsqlOp::Eq | RsqlOp::Neq | RsqlOp::Null(_)),
        FieldType::Uuid => matches!(
            op,
            RsqlOp::Eq | RsqlOp::Neq | RsqlOp::In | RsqlOp::Out | RsqlOp::Null(_)
        ),
        FieldType::Date | FieldType::Timestamp | FieldType::Time => matches!(
            op,
            RsqlOp::Eq
                | RsqlOp::Neq
                | RsqlOp::Gt
                | RsqlOp::Ge
                | RsqlOp::Lt
                | RsqlOp::Le
                | RsqlOp::Between
                | RsqlOp::In
                | RsqlOp::Out
                | RsqlOp::Null(_)
        ),
    }
}

/// A built WHERE/ORDER BY fragment plus the ordered text parameters to bind.
#[derive(Debug)]
pub struct BuiltQuery {
    /// WHERE fragment WITHOUT a leading `WHERE`/`AND` (empty when there is no filter).
    pub where_sql: String,
    /// ORDER BY fragment WITH a leading space (e.g. ` ORDER BY u.name ASC`), or empty.
    pub order_sql: String,
    /// Values to bind, in `$start_index`, `$start_index+1`, … order.
    pub params: Vec<String>,
}

struct Builder<'a> {
    fields: &'a FieldMap,
    params: Vec<String>,
    /// Next placeholder number (1-based). Callers pass the first free index after their
    /// own fixed params (e.g. tenant_id occupies `$1`, so filtering starts at `$2`).
    next: usize,
}

impl<'a> Builder<'a> {
    fn ph(&mut self, value: String, cast: Option<&str>) -> String {
        let n = self.next;
        self.next += 1;
        self.params.push(value);
        match cast {
            Some(t) => format!("${}::{}", n, t),
            None => format!("${}", n),
        }
    }

    fn build_node(&mut self, node: &FilterNode) -> Result<String, AppError> {
        match node {
            FilterNode::And(children) => {
                let parts: Result<Vec<_>, _> =
                    children.iter().map(|c| self.build_node(c)).collect();
                Ok(format!("({})", parts?.join(" AND ")))
            }
            FilterNode::Or(children) => {
                let parts: Result<Vec<_>, _> =
                    children.iter().map(|c| self.build_node(c)).collect();
                Ok(format!("({})", parts?.join(" OR ")))
            }
            FilterNode::Leaf { field, op, values } => self.build_leaf(field, op, values),
        }
    }

    fn build_leaf(
        &mut self,
        field: &str,
        op: &RsqlOp,
        values: &[String],
    ) -> Result<String, AppError> {
        let spec = lookup(self.fields, field)?;
        if !op_valid_for_type(op, spec.ty) {
            return Err(AppError::Validation(format!(
                "operator {} is not valid for {:?} field '{}'",
                op.display(),
                spec.ty,
                field
            )));
        }
        let col = spec.column;
        // LIKE-family operators compare as text, so they never carry a type cast.
        let is_like = matches!(
            op,
            RsqlOp::Like | RsqlOp::Ilike | RsqlOp::Contains | RsqlOp::Starts | RsqlOp::Ends
        );
        let cast = if is_like { None } else { spec.ty.cast() };

        match op {
            RsqlOp::Null(is_null) => Ok(if *is_null {
                format!("{} IS NULL", col)
            } else {
                format!("{} IS NOT NULL", col)
            }),
            RsqlOp::Eq | RsqlOp::Neq | RsqlOp::Gt | RsqlOp::Ge | RsqlOp::Lt | RsqlOp::Le => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(v, cast);
                let cmp = match op {
                    RsqlOp::Eq => "=",
                    RsqlOp::Neq => "!=",
                    RsqlOp::Gt => ">",
                    RsqlOp::Ge => ">=",
                    RsqlOp::Lt => "<",
                    RsqlOp::Le => "<=",
                    _ => unreachable!(),
                };
                Ok(format!("{} {} {}", col, cmp, ph))
            }
            RsqlOp::Like => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(v, None);
                Ok(format!("{} LIKE {}", col, ph))
            }
            RsqlOp::Ilike => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(v, None);
                Ok(format!("{} ILIKE {}", col, ph))
            }
            RsqlOp::Contains => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(format!("%{}%", v), None);
                Ok(format!("{} ILIKE {}", col, ph))
            }
            RsqlOp::Starts => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(format!("{}%", v), None);
                Ok(format!("{} ILIKE {}", col, ph))
            }
            RsqlOp::Ends => {
                let v = values.first().cloned().unwrap_or_default();
                let ph = self.ph(format!("%{}", v), None);
                Ok(format!("{} ILIKE {}", col, ph))
            }
            RsqlOp::In | RsqlOp::Out => {
                if values.is_empty() {
                    return Err(AppError::Validation(format!(
                        "{} requires at least one value for field '{}'",
                        op.display(),
                        field
                    )));
                }
                let phs: Vec<String> =
                    values.iter().map(|v| self.ph(v.clone(), cast)).collect();
                let kw = if matches!(op, RsqlOp::In) { "IN" } else { "NOT IN" };
                Ok(format!("{} {} ({})", col, kw, phs.join(", ")))
            }
            RsqlOp::Between => {
                if values.len() != 2 {
                    return Err(AppError::Validation(format!(
                        "=between= requires exactly 2 values for field '{}', got {}",
                        field,
                        values.len()
                    )));
                }
                let p1 = self.ph(values[0].clone(), cast);
                let p2 = self.ph(values[1].clone(), cast);
                Ok(format!("{} BETWEEN {} AND {}", col, p1, p2))
            }
        }
    }
}

/// Build the WHERE and ORDER BY fragments for a list query.
///
/// * `filter` — parsed RSQL tree (from `q`), or `None`.
/// * `sort` — parsed sort specs (from `sort`); unknown or sensitive fields are rejected.
/// * `fields` — the endpoint's field allowlist.
/// * `start_index` — the first free `$n` placeholder (1-based) after the caller's own
///   fixed bind params. e.g. pass `2` when `$1` is already the tenant_id.
///
/// Returned `params` bind in order starting at `start_index`.
pub fn build(
    filter: Option<&FilterNode>,
    sort: &[SortSpec],
    fields: &FieldMap,
    start_index: usize,
) -> Result<BuiltQuery, AppError> {
    let mut b = Builder {
        fields,
        params: Vec::new(),
        next: start_index,
    };

    let where_sql = match filter {
        Some(node) => b.build_node(node)?,
        None => String::new(),
    };

    // ORDER BY: every sort field must be a known, non-sensitive column.
    let mut order_parts: Vec<String> = Vec::new();
    for s in sort {
        let spec = fields
            .iter()
            .find(|f| f.api_name == s.field)
            .ok_or_else(|| AppError::Validation(format!("sort field '{}' does not exist", s.field)))?;
        if spec.sensitive {
            return Err(AppError::Validation(format!(
                "field '{}' is not sortable",
                s.field
            )));
        }
        let dir = if s.desc { "DESC" } else { "ASC" };
        order_parts.push(format!("{} {}", spec.column, dir));
    }
    let order_sql = if order_parts.is_empty() {
        String::new()
    } else {
        format!(" ORDER BY {}", order_parts.join(", "))
    };

    Ok(BuiltQuery {
        where_sql,
        order_sql,
        params: b.params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::rsql::{parse_rsql, parse_sort};

    const USER_FIELDS: &[FieldSpec] = &[
        FieldSpec { api_name: "status", column: "u.status", ty: FieldType::Text, sensitive: false },
        FieldSpec { api_name: "email", column: "i.email", ty: FieldType::Text, sensitive: false },
        FieldSpec { api_name: "mfaEnabled", column: "i.mfa_enabled", ty: FieldType::Bool, sensitive: false },
        FieldSpec { api_name: "createdAt", column: "u.created_at", ty: FieldType::Timestamp, sensitive: false },
        FieldSpec { api_name: "passwordHash", column: "i.password_hash", ty: FieldType::Text, sensitive: true },
    ];

    #[test]
    fn simple_eq_casts_nothing_for_text() {
        let f = parse_rsql("status==active").unwrap();
        let b = build(Some(&f), &[], USER_FIELDS, 2).unwrap();
        assert_eq!(b.where_sql, "u.status = $2");
        assert_eq!(b.params, vec!["active"]);
    }

    #[test]
    fn bool_gets_cast() {
        let f = parse_rsql("mfaEnabled==true").unwrap();
        let b = build(Some(&f), &[], USER_FIELDS, 2).unwrap();
        assert_eq!(b.where_sql, "i.mfa_enabled = $2::boolean");
    }

    #[test]
    fn contains_is_ilike_wildcard() {
        let f = parse_rsql("email=contains=gmail").unwrap();
        let b = build(Some(&f), &[], USER_FIELDS, 2).unwrap();
        assert_eq!(b.where_sql, "i.email ILIKE $2");
        assert_eq!(b.params, vec!["%gmail%"]);
    }

    #[test]
    fn and_or_grouping_and_param_numbering() {
        let f = parse_rsql("status==active;(status==pending,status==trial)").unwrap();
        let b = build(Some(&f), &[], USER_FIELDS, 2).unwrap();
        assert_eq!(b.where_sql, "(u.status = $2 AND (u.status = $3 OR u.status = $4))");
        assert_eq!(b.params.len(), 3);
    }

    #[test]
    fn between_timestamp() {
        let f = parse_rsql("createdAt=between=(2024-01-01T00:00:00Z,2025-01-01T00:00:00Z)").unwrap();
        let b = build(Some(&f), &[], USER_FIELDS, 2).unwrap();
        assert_eq!(
            b.where_sql,
            "u.created_at BETWEEN $2::timestamptz AND $3::timestamptz"
        );
    }

    #[test]
    fn sort_maps_to_column() {
        let b = build(None, &parse_sort("-createdAt,status"), USER_FIELDS, 2).unwrap();
        assert_eq!(b.order_sql, " ORDER BY u.created_at DESC, u.status ASC");
    }

    #[test]
    fn unknown_field_rejected() {
        let f = parse_rsql("bogus==1").unwrap();
        assert!(build(Some(&f), &[], USER_FIELDS, 2).is_err());
    }

    #[test]
    fn sensitive_field_not_filterable() {
        let f = parse_rsql("passwordHash==x").unwrap();
        let err = build(Some(&f), &[], USER_FIELDS, 2).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn sensitive_field_not_sortable() {
        assert!(build(None, &parse_sort("passwordHash"), USER_FIELDS, 2).is_err());
    }

    #[test]
    fn unknown_sort_field_rejected() {
        assert!(build(None, &parse_sort("bogus"), USER_FIELDS, 2).is_err());
    }

    #[test]
    fn wrong_operator_for_type_rejected() {
        // =gt= on a text field is invalid.
        let f = parse_rsql("status=gt=x").unwrap();
        assert!(build(Some(&f), &[], USER_FIELDS, 2).is_err());
    }
}
