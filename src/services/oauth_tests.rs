//! Unit tests for the pure parts of the OAuth service: provider parsing, endpoint building,
//! PKCE, claim normalization and Microsoft issuer / directory rules. No I/O.

use super::*;
use serde_json::json;

const ORG_TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";

fn cfg(tenant: Option<&str>) -> OauthConfig {
    OauthConfig {
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        redirect_url: "https://app.example.com/oauth/callback".to_string(),
        tenant: tenant.map(String::from),
        allow_signup: None,
    }
}

fn claims(v: serde_json::Value) -> IdTokenClaims {
    serde_json::from_value(v).expect("claims")
}

fn ms_claims(tid: &str, xms_edov: Option<serde_json::Value>) -> IdTokenClaims {
    IdTokenClaims {
        iss: format!("{}/{}/v2.0", MICROSOFT_LOGIN_BASE, tid),
        sub: "pairwise-sub".to_string(),
        nonce: None,
        email: Some(" Jane.Doe@Contoso.com ".to_string()),
        email_verified: None,
        given_name: None,
        family_name: None,
        name: Some("Jane Doe".to_string()),
        oid: Some("oid-1".to_string()),
        tid: Some(tid.to_string()),
        xms_edov,
    }
}

fn google(extra: serde_json::Value) -> IdTokenClaims {
    let mut base = json!({ "iss": "https://accounts.google.com", "sub": "1234567890" });
    base.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    claims(base)
}

fn is_unauthorized(r: Result<(), AppError>) -> bool {
    matches!(r, Err(AppError::Unauthorized(_)))
}

fn is_forbidden(r: Result<(), AppError>) -> bool {
    matches!(r, Err(AppError::Forbidden(_)))
}

// ---- Provider -------------------------------------------------------------------------

#[test]
fn provider_parse_accepts_known_providers_and_round_trips() {
    for p in [Provider::Google, Provider::Microsoft] {
        assert_eq!(Provider::parse(p.as_str()).unwrap(), p);
    }
}

#[test]
fn provider_parse_rejects_unknown_and_is_case_sensitive() {
    for bad in ["github", "", "Google", "MICROSOFT", " google"] {
        assert!(
            matches!(Provider::parse(bad), Err(AppError::NotFound(_))),
            "{bad:?} should be rejected"
        );
    }
}

// ---- Endpoints ------------------------------------------------------------------------

#[test]
fn google_endpoints_ignore_microsoft_authority() {
    let e = ProviderEndpoints::default();
    let c = cfg(Some(ORG_TID));
    assert_eq!(e.auth_url(Provider::Google, &c), GOOGLE_AUTH_URL);
    assert_eq!(e.token_url(Provider::Google, &c), GOOGLE_TOKEN_URL);
    assert_eq!(e.jwks_url(Provider::Google, &c), GOOGLE_JWKS_URL);
}

#[test]
fn microsoft_endpoints_use_configured_authority() {
    let e = ProviderEndpoints::default();
    assert_eq!(
        e.auth_url(Provider::Microsoft, &cfg(None)),
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    );
    assert_eq!(
        e.token_url(Provider::Microsoft, &cfg(Some(ORG_TID))),
        format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", ORG_TID)
    );
    assert_eq!(
        e.jwks_url(Provider::Microsoft, &cfg(Some("organizations"))),
        "https://login.microsoftonline.com/organizations/discovery/v2.0/keys"
    );
}

#[test]
fn microsoft_authority_defaults_to_common_when_blank() {
    assert_eq!(microsoft_authority(&cfg(None)), "common");
    assert_eq!(microsoft_authority(&cfg(Some(""))), "common");
    assert_eq!(microsoft_authority(&cfg(Some("   "))), "common");
    assert_eq!(microsoft_authority(&cfg(Some("  consumers "))), "consumers");
}

#[test]
fn custom_endpoints_are_used_verbatim() {
    let e = ProviderEndpoints {
        google_auth_url: "http://idp/g/auth".into(),
        google_token_url: "http://idp/g/token".into(),
        google_jwks_url: "http://idp/g/jwks".into(),
        microsoft_login_base: "http://idp/ms".into(),
    };
    assert_eq!(e.token_url(Provider::Google, &cfg(None)), "http://idp/g/token");
    assert_eq!(
        e.jwks_url(Provider::Microsoft, &cfg(None)),
        "http://idp/ms/common/discovery/v2.0/keys"
    );
}

// ---- Random tokens / PKCE -------------------------------------------------------------

#[test]
fn random_token_is_256_bit_url_safe_and_unique() {
    let tokens: std::collections::HashSet<String> = (0..256).map(|_| random_token()).collect();
    assert_eq!(tokens.len(), 256, "tokens must not repeat");
    for t in &tokens {
        assert_eq!(t.len(), 43, "32 bytes base64url without padding");
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}

#[test]
fn pkce_challenge_matches_rfc7636_example() {
    // RFC 7636 Appendix B.
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn pkce_verifier_from_random_token_is_rfc_compliant() {
    // RFC 7636 §4.1: 43..=128 chars of [A-Z a-z 0-9 - . _ ~].
    let v = random_token();
    assert!((43..=128).contains(&v.len()));
    let c = pkce_challenge(&v);
    assert_ne!(c, v);
    assert_eq!(c.len(), 43);
}

// ---- Claim helpers --------------------------------------------------------------------

#[test]
fn claim_is_true_accepts_bool_and_string_forms_only() {
    assert!(claim_is_true(&Some(json!(true))));
    assert!(claim_is_true(&Some(json!("true"))));
    assert!(claim_is_true(&Some(json!("TRUE"))));
    assert!(!claim_is_true(&Some(json!(false))));
    assert!(!claim_is_true(&Some(json!("false"))));
    assert!(!claim_is_true(&Some(json!("yes"))));
    assert!(!claim_is_true(&Some(json!(1))));
    assert!(!claim_is_true(&Some(json!(null))));
    assert!(!claim_is_true(&None));
}

#[test]
fn non_empty_trims_and_drops_blank() {
    assert_eq!(non_empty(None), None);
    assert_eq!(non_empty(Some("".into())), None);
    assert_eq!(non_empty(Some(" \t ".into())), None);
    assert_eq!(non_empty(Some("  x y ".into())).as_deref(), Some("x y"));
}

#[test]
fn id_token_claims_tolerate_extra_and_missing_optional_claims() {
    let c = claims(json!({
        "iss": "https://accounts.google.com",
        "sub": "s",
        "aud": ["a", "b"],
        "azp": "x",
        "hd": "example.com",
        "picture": "https://…",
    }));
    assert_eq!(c.sub, "s");
    assert!(c.email.is_none() && c.nonce.is_none() && c.tid.is_none());
}

#[test]
fn oauth_config_deserializes_camel_case_with_optional_defaults() {
    let c: OauthConfig = serde_json::from_value(json!({
        "clientId": "id", "clientSecret": "sec", "redirectUrl": "https://r"
    }))
    .unwrap();
    assert_eq!((c.client_id.as_str(), c.redirect_url.as_str()), ("id", "https://r"));
    assert!(c.tenant.is_none() && c.allow_signup.is_none());

    let c: OauthConfig = serde_json::from_value(json!({
        "clientId": "id", "clientSecret": "sec", "redirectUrl": "https://r",
        "tenant": "organizations", "allowSignup": false
    }))
    .unwrap();
    assert_eq!(c.tenant.as_deref(), Some("organizations"));
    assert_eq!(c.allow_signup, Some(false));

    // A config missing a required field is treated as "not configured" by the loader.
    assert!(serde_json::from_value::<OauthConfig>(json!({ "clientId": "id" })).is_err());
}

// ---- Microsoft issuer / directory rules -----------------------------------------------

#[test]
fn microsoft_issuer_must_match_tid() {
    let mut c = ms_claims(ORG_TID, None);
    assert!(OauthService::check_microsoft_issuer(&cfg(None), &c).is_ok());
    c.iss = format!("{}/{}/v2.0", MICROSOFT_LOGIN_BASE, MICROSOFT_CONSUMERS_TENANT_ID);
    assert!(is_unauthorized(OauthService::check_microsoft_issuer(&cfg(None), &c)));
}

#[test]
fn microsoft_issuer_rejects_v1_lookalike_and_foreign_hosts() {
    for iss in [
        format!("https://sts.windows.net/{}/", ORG_TID),
        format!("https://login.microsoftonline.com/{}/v2.0/", ORG_TID),
        format!("https://evil.example.com/{}/v2.0", ORG_TID),
        format!("https://login.microsoftonline.com/{}", ORG_TID),
    ] {
        let mut c = ms_claims(ORG_TID, None);
        c.iss = iss.clone();
        assert!(is_unauthorized(OauthService::check_microsoft_issuer(&cfg(None), &c)), "{iss}");
    }
}

#[test]
fn microsoft_issuer_requires_tid() {
    let mut c = ms_claims(ORG_TID, None);
    c.tid = None;
    assert!(is_unauthorized(OauthService::check_microsoft_issuer(&cfg(None), &c)));
}

#[test]
fn microsoft_authority_restricts_directories() {
    let org = ms_claims(ORG_TID, None);
    let personal = ms_claims(MICROSOFT_CONSUMERS_TENANT_ID, None);
    let check = |t: &str, c: &IdTokenClaims| OauthService::check_microsoft_issuer(&cfg(Some(t)), c);
    assert!(check("common", &org).is_ok());
    assert!(check("common", &personal).is_ok());
    assert!(check("organizations", &org).is_ok());
    assert!(is_forbidden(check("organizations", &personal)));
    assert!(check("consumers", &personal).is_ok());
    assert!(is_forbidden(check("consumers", &org)));
    assert!(check(ORG_TID, &org).is_ok());
    assert!(is_forbidden(check("00000000-0000-0000-0000-000000000001", &org)));
}

#[test]
fn microsoft_authority_keywords_and_guids_are_case_insensitive() {
    let org = ms_claims(ORG_TID, None);
    let personal = ms_claims(MICROSOFT_CONSUMERS_TENANT_ID, None);
    let check = |t: &str, c: &IdTokenClaims| OauthService::check_microsoft_issuer(&cfg(Some(t)), c);
    assert!(is_forbidden(check("Organizations", &personal)));
    assert!(is_forbidden(check("CONSUMERS", &org)));
    assert!(check(&ORG_TID.to_uppercase(), &org).is_ok());
}

#[test]
fn microsoft_domain_authority_cannot_pin_tid() {
    // A domain-name authority can't be compared to `tid`; Microsoft scopes sign-in itself.
    let org = ms_claims(ORG_TID, None);
    assert!(OauthService::check_microsoft_issuer(&cfg(Some("contoso.onmicrosoft.com")), &org).is_ok());
}

// ---- Profile normalization ------------------------------------------------------------

#[test]
fn microsoft_profile_uses_tid_oid_and_requires_edov_for_org_email() {
    let p = OauthService::profile_from_claims(Provider::Microsoft, ms_claims(ORG_TID, None)).unwrap();
    assert_eq!(p.provider_user_id, format!("{}:oid-1", ORG_TID));
    assert_eq!(p.email.as_deref(), Some("jane.doe@contoso.com"));
    assert!(!p.email_verified);
    assert_eq!(p.first_name.as_deref(), Some("Jane"));
    assert_eq!(p.last_name.as_deref(), Some("Doe"));

    for edov in [json!(true), json!("true")] {
        let p = OauthService::profile_from_claims(Provider::Microsoft, ms_claims(ORG_TID, Some(edov))).unwrap();
        assert!(p.email_verified);
    }
    let p = OauthService::profile_from_claims(Provider::Microsoft, ms_claims(ORG_TID, Some(json!(false)))).unwrap();
    assert!(!p.email_verified);

    let p = OauthService::profile_from_claims(
        Provider::Microsoft,
        ms_claims(MICROSOFT_CONSUMERS_TENANT_ID, None),
    )
    .unwrap();
    assert!(p.email_verified, "personal accounts' emails are verified by Microsoft");
}

#[test]
fn microsoft_profile_ignores_pairwise_sub() {
    let mut a = ms_claims(ORG_TID, None);
    let mut b = ms_claims(ORG_TID, None);
    a.sub = "sub-for-app-1".into();
    b.sub = "sub-for-app-2".into();
    let pa = OauthService::profile_from_claims(Provider::Microsoft, a).unwrap();
    let pb = OauthService::profile_from_claims(Provider::Microsoft, b).unwrap();
    assert_eq!(pa.provider_user_id, pb.provider_user_id, "same person across app registrations");
}

#[test]
fn microsoft_profile_requires_object_id() {
    for oid in [None, Some("".to_string()), Some("   ".to_string())] {
        let mut c = ms_claims(ORG_TID, None);
        c.oid = oid;
        assert!(matches!(
            OauthService::profile_from_claims(Provider::Microsoft, c),
            Err(AppError::Unauthorized(_))
        ));
    }
}

#[test]
fn google_profile_uses_sub_and_email_verified() {
    let p = OauthService::profile_from_claims(
        Provider::Google,
        google(json!({
            "email": "user@gmail.com", "email_verified": true,
            "given_name": "Ada", "family_name": "Lovelace",
            // Microsoft-only claims are ignored for Google.
            "oid": "x", "tid": "y", "xms_edov": true
        })),
    )
    .unwrap();
    assert_eq!(p.provider_user_id, "1234567890");
    assert!(p.email_verified);
    assert_eq!(p.first_name.as_deref(), Some("Ada"));
    assert_eq!(p.last_name.as_deref(), Some("Lovelace"));
}

#[test]
fn google_email_verified_accepts_string_and_defaults_to_false() {
    let verified = |v: serde_json::Value| {
        let mut extra = json!({ "email": "u@gmail.com" });
        if !v.is_null() {
            extra["email_verified"] = v;
        }
        OauthService::profile_from_claims(Provider::Google, google(extra))
            .unwrap()
            .email_verified
    };
    assert!(verified(json!("true")));
    assert!(!verified(json!(false)));
    assert!(!verified(json!("false")));
    assert!(!verified(serde_json::Value::Null));
}

#[test]
fn email_is_trimmed_lowercased_and_never_verified_when_absent() {
    let p = OauthService::profile_from_claims(
        Provider::Google,
        google(json!({ "email": "  MiXeD@Example.COM ", "email_verified": true })),
    )
    .unwrap();
    assert_eq!(p.email.as_deref(), Some("mixed@example.com"));

    for extra in [json!({ "email_verified": true }), json!({ "email": "   ", "email_verified": true })] {
        let p = OauthService::profile_from_claims(Provider::Google, google(extra)).unwrap();
        assert!(p.email.is_none());
        assert!(!p.email_verified, "verified flag without an email must be false");
    }
}

#[test]
fn names_fall_back_to_splitting_full_name() {
    let names = |extra: serde_json::Value| {
        let p = OauthService::profile_from_claims(Provider::Google, google(extra)).unwrap();
        (p.first_name, p.last_name)
    };
    let s = |v: &str| Some(v.to_string());
    assert_eq!(names(json!({ "name": "Cher" })), (s("Cher"), None));
    assert_eq!(names(json!({ "name": "Mary Ann Smith" })), (s("Mary"), s("Ann Smith")));
    assert_eq!(names(json!({ "name": "  Jane   Doe  " })), (s("Jane"), s("Doe")));
    assert_eq!(names(json!({ "name": "   " })), (None, None));
    assert_eq!(names(json!({})), (None, None));
    // Structured names win over `name`, even when only one part is present.
    assert_eq!(names(json!({ "given_name": "Ada", "name": "Someone Else" })), (s("Ada"), None));
    assert_eq!(names(json!({ "family_name": "Lovelace", "name": "X Y" })), (None, s("Lovelace")));
    // Blank structured names are ignored, so `name` is used.
    assert_eq!(names(json!({ "given_name": " ", "family_name": "", "name": "A B" })), (s("A"), s("B")));
}
