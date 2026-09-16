//! W3C Trace Context (`traceparent`) ingress middleware.
//!
//! authrs is a **downstream, non-originating** service: callers (e.g. service-kit
//! / architect-sdk consumers) send a `traceparent` header, and this middleware
//! reads the `trace-id` from it and attaches it to a `tracing` span so every log
//! line for the request carries `trace_id` — with no change at the log call site.
//!
//! It never generates a trace: when the header is absent or malformed, `trace_id`
//! is empty (this service does not start traces). When a valid header is present,
//! the original `traceparent` is echoed back on the response so callers can
//! correlate.
//!
//! Header format (W3C): `00-<32-hex trace-id>-<16-hex span-id>-<2-hex flags>`.

use axum::{
    extract::Request,
    http::{header::HeaderValue, HeaderName},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;

/// Header name carrying the W3C trace context.
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// The trace id resolved for the current request, stored as a request extension
/// so handlers can read it explicitly. Empty when no valid header was passed.
#[derive(Clone, Debug)]
pub struct TraceId(pub String);

/// Extract and validate the `trace-id` (32 hex) from a W3C `traceparent` value.
/// Returns `None` when the shape is wrong, the version is `ff` (invalid), or the
/// trace id is all zeros — in which case the request carries no usable trace.
fn parse_trace_id(traceparent: &str) -> Option<String> {
    let mut it = traceparent.trim().split('-');
    let version = it.next()?;
    let trace_id = it.next()?;
    let parent_id = it.next()?;
    let flags = it.next()?;
    if it.next().is_some() {
        return None; // more than 4 segments
    }
    let is_hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex(version, 2) || !is_hex(trace_id, 32) || !is_hex(parent_id, 16) || !is_hex(flags, 2) {
        return None;
    }
    if version.eq_ignore_ascii_case("ff") {
        return None;
    }
    let tid = trace_id.to_ascii_lowercase();
    if tid.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(tid)
}

/// Ingress middleware: resolve the incoming trace id, attach it to the request
/// span (so every log line carries `trace_id`) and to request extensions, and
/// echo the original `traceparent` back on the response when it was valid.
///
/// Apply once on the top-level router:
/// ```ignore
/// let app = router.layer(axum::middleware::from_fn(trace_id_middleware));
/// ```
pub async fn trace_id_middleware(mut request: Request, next: Next) -> Response {
    // Non-originating: use only the trace id passed in; empty when absent/invalid.
    let trace_id = request
        .headers()
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_trace_id)
        .unwrap_or_default();

    // Preserve the original header (only when the trace id was valid) to echo back.
    let echo = if trace_id.is_empty() {
        None
    } else {
        request
            .headers()
            .get(TRACEPARENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Make the id available to handlers that want it explicitly.
    request.extensions_mut().insert(TraceId(trace_id.clone()));

    let span = tracing::info_span!(
        "request",
        trace_id = %trace_id,
        method = %method,
        path = %path,
    );

    async move {
        let mut response = next.run(request).await;
        if let Some(tp) = echo {
            if let Ok(value) = HeaderValue::from_str(&tp) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static(TRACEPARENT_HEADER), value);
            }
        }
        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_traceparent() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(
            parse_trace_id(tp).as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    #[test]
    fn rejects_malformed_and_zero() {
        assert_eq!(parse_trace_id("garbage"), None);
        assert_eq!(parse_trace_id("00-abc-00f067aa0ba902b7-01"), None); // short trace-id
        assert_eq!(
            parse_trace_id("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            None
        ); // invalid version
        assert_eq!(
            parse_trace_id("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
            None
        ); // all-zero trace-id
    }
}
