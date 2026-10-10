Test-only fixtures. The RSA keys here sign fake ID tokens for the OAuth tests (served to the
service through a mock JWKS endpoint). They are not used anywhere outside `cargo test` and
must never be configured as real signing keys.
