# Oxide OIDC Token Exchanger

A service that exchanges OIDC identity tokens with GitHub and Oxide short-lived
tokens. The source is released under the MPL 2.0 license.

The recommended way to interact with the service from GitHub Actions is to use
[oxidecomputer/oidcx-action].

[oxidecomputer/oidcx-action]: https://github.com/oxidecomputer/oidcx-action

## Exchange flow

The server exposes a single endpoint, `POST /exchange`, which exchanges a JWT
from a trusted OpenID Connect identity provider with a temporary token from one
of the supported services.

The JWT must have an `aud` (audience) matching the protocol and hostname of the
oidcx instance (for example `https://oidcx.example.com`). This
ensures a JWT meant for oidcx cannot be used for other services.

The claims in the JWT and in the request must adhere to the configured
authorization policy. The authorization policy differs between deployment, so
it's recommended to read the deployment's documentation to see what requests
will be allowed.

Once a request is authorized, a JSON payload with a single `access_token` field
will be returned, containing the requested access token.

### Requesting GitHub tokens

To request GitHub tokens, the JSON request body must containg the fields:

* `caller_identity`: JWT token used for authorizing the request.
* `service`: must be `github`.
* `repositories`: list of repositories to request access to. They must all
  belong to the same organization or user. Issue separate exchange calls if you
  need access to repositories belonging to different users or orgs.
* `permissions`: list of permissions the token should be granted. Each
  permission is in the form of `scope:level`, where the scope is [one of the
  scopes supported by GitHub App installation tokens][gh-perms] and the level is
  either `read` or `write`.

An example of a valid request:

```json
{
  "jwt": "eyJhbGciOiJIUz...",
  "service": "github",
  "repositories": ["oxidecomputer/oidcx"],
  "permissions": ["contents:write", "pull_requests:write"]
}
```

Tokens will be valid for an hour.

Note that the permissions that can be granted and the repositories that can be
accessed depend on the permissions the underlying GitHub App generating the
token has, and whether it is installed in the repositories you are trying to
access. Even if a request is authorized by oidcx, it might be rejected
if the GitHub App cannot generate the requested token.

### Requesting Oxide silo tokens

To request tokens to access an Oxide silo, the JSON request must contain the
fields:

* `caller_identity`: JWT token used for authorizing the request.
* `service`: must be `oxide`.
* `silo`: URL of the silothe token is requested for.
* `duration` number of seconds the token should be valid for.

An example of a valid request:

```json
{
  "jwt": "eyJhbGciOiJIUz...",
  "service": "github",
  "silo": "https://oxide.sys.rack2.eng.oxide.computer",
  "duration": 3600
}
```

Note that credentials for the requested silo must be present in oidcx's
configuration. The resulting token will have the same level of access as the
credential in the configuration.

[gh-perms]: https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps?apiVersion=2022-11-28

## Authorization policy

The authorization policy is defined using the [Polar language][polar].
oidcx will check whether the `allow_request(claims, request)` Polar
query is authorized, passing the OIDC claims in the `claims` parameter and the
`Oxide` or `GitHub` token request in the `request` parameter.

A very simple authorization policy can be:

```polar
allow_request(claims, request) if
  claims.iss == "https://token.actions.githubusercontent.com" and
  claims.repository == "oxidecomputer/oidcx" and
  request matches GitHub and
  request.repository == "oxidecomputer/oidcx-action" and
  request.permission == "contents:write";
```

This policy checks whether the OIDC claims indicate the request came from GitHub
Actions (with `claims.iss`) and the repository requesting the token is the
intended one (with `claims.repository`). It then checks that the request is a
GitHub token request, and that the requested repository and permission is the
allowed one.

More advanced Polar policies can be written. For example:

```polar
allow_request(claims, request) if
  claims.iss == "https://token.actions.githubusercontent.com" and
  claims.repository_owner == "oxidecomputer" and
  allow_from_github_actions(claims, request);

allow_from_github_actions(claims, request: GitHub) if
  claims.repository == request.repository and
  request.permission == "contents:write";

allow_from_github_actions(claims, request: Oxide) if
  request.silo == "https://oxide.sys.rack2.eng.oxide.computer" and
  request.duration <= 3600 and
  claims.repository in [
    "oxidecomputer/oidc-exchnage",
    "oxidecomputer/oidcx-action",
  ];
```

The policy above defines rules in `allow_request()` that all requests authorized
by `allow_from_github_actions()` must abide by, a policy allowing a repository
to get a GitHub token with write access to itself (by checking that the
requested repository matches the claimed repository), and a request allowing two
repositories to request an Oxide token.

### Polar scheme for `claims`

The `claims` argument in Polar policies contain all of the claims included in
the OIDC JWT. It must include `iss` and `aud` (note that the audience is checked
by oidcx *before* the Polar policy, so you don't need to check it
again), and the rest of the claims depend on what your identity provider claims.

For GitHub Actions, [GitHub provides a list of included claims][gha-claims].

### Polar scheme for `request` of type `Oxide`

The `request` argument in Polar policies can be of type `Oxide` when the user
requested an Oxide token. The two fields available are `silo` (the URL to the
silo) and `duration` (the number of seconds the token will be valid for).

### Polar scheme for `request` of type `GitHub`

The `request` argument in Polar policies can be of type `GitHub` when the user
requested a GitHub token. The two fields available are `repository` (the name of
one of the repositories being requested) and `permission` (the name of one of
the requested permissions).

To simplify how policies are written, when authorizing GitHub token requests
oidcx will individually test whether all permutations of repositories
and permissions are valid, and reject the request if any of them are not. This
means in the policy you only check one `(repository, permission)` permutation at
a time.

[polar]: https://www.osohq.com/docs/oss/learn/polar-foundations.html
[gha-claims]: https://docs.github.com/en/actions/reference/security/oidc

## Configuration

The main configuration of the service is defined into a TOML file. Multiple
files can be passed to the command line, and they will be merged. If no path to
a configuration file is passed the `settings.toml` file from the current
directory will be loaded.

File-backed parameters (the Oxide silo manifest and its credentials, and the
GitHub App private key, all specified as `{ path = "..." }`) are resolved
relative to the directory in the `PARAMS_BASE_PATH` environment variable, read
once at startup. When `PARAMS_BASE_PATH` is unset, those paths are used as-is
(absolute, or relative to the working directory).

```toml
# Path to the Polar file defining the authorization policy. Required.
policy_path = "path/to/policy.polar"

# Expected content of the `aud` claim in JWTs. JWTs with different audiences
# will be rejected. For compatibility with oxidecomputer/oidcx-action,
# this must be the URL the service is deployed to. It's strongly recommended to
# use the server URL in other scenarios too. Required.
audience = "https://hostname.of.oidcx.example"

# Port to bind the service to. Optional, defaults to 8080.
port = 8080

# Directory to store log files into. Optional, if missing logs will be emitted
# to stdout.
log_directory = "path/to/logs"

# The [[providers]] block defines one OIDC identity provider authorized to issue
# JWTs accepted by oidcx. Multiple blocks can be provided to support
# more than one IdP. The URL needs to point to the provider's OpenID config URL.
# At least one is required for oidcx to do anything useful.
[[providers]]
url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"

# The [oxide] block enables issuing Oxide silo tokens. The block is optional,
# and if omitted no Oxide silo tokens will be issued.
#
# Because settings.toml is baked identically into every environment, it cannot
# enumerate the silos itself (their number and names differ per environment).
# Instead `silos` is a v-api SerializedParam that points at a JSON manifest on
# the parameters volume via a fixed path (the same path everywhere; only the
# file it points at changes per environment).
[oxide]
silos = { path = "/params/oxide-silos.json" }

# The manifest is a JSON object mapping each silo url to the credential used to
# mint tokens for it. Each credential is a v-api StringParam: either an inline
# secret or a { "path": "..." } reference to a secret file on the volume. For
# example, the file at /params/oxide-silos.json might contain:
#
#   {
#     "https://oxide.sys.rack2.eng.oxide.computer": { "path": "/params/oxide-token" },
#     "https://example.sys.rack2.eng.oxide.computer": { "path": "/params/example-token" }
#   }

# The [github] block defines the GitHub App used to issue GitHub tokens. The app
# must be installed on all repositories a token can be generated for, and must
# have all the permissions a repository might decide to request. The block is
# optional, and if omitted no GitHub tokens will be issued.
[github]
client_id = "Iv2AAAAAAAAAAAAAAAAA"
private_key = { path = "path/to/private-key.pem" }
```
