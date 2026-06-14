# Test fixtures

`test_rsa_key.pem` is a **throwaway RSA keypair generated solely for unit
tests** of JWT validation (`src/oidc.rs`). It is not used by the running
service and protects nothing. Its public-key parameters (`n`, `e`) are embedded
as constants in the test module so the test can build a JWKS that matches this
signing key.

Do not use this key for anything real.
