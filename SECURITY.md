<!-- ABOUTME: Security policy: how to report a vulnerability, supported versions, disclosure timeline, scope -->
<!-- ABOUTME: (including the bundled quiche/BoringSSL shim) and the advisory response process for native code. -->
# Security policy

## Reporting a vulnerability

Please don't open a public issue for a suspected vulnerability. Use
GitHub's private vulnerability reporting instead: "Report a
vulnerability" under the repository's Security tab
(<https://github.com/mpenet/enso/security/advisories/new>).

Include the enso version or commit, the JDK version and platform, the
protocol involved (HTTP/1.1, HTTP/2 over TLS or h2c, HTTP/3, WebSocket),
the server options in use, and a reproducer: a byte sequence, a client
command line or a test. Don't send proof-of-concept traffic to servers you
don't own.

For hardening advice when running enso, see
[doc/deployment.md](doc/deployment.md).

## Supported versions

enso is pre-1.0 (`1.0.0-alphaN`). Only the latest release gets security
fixes, and a fix ships as the next release. This section will list
supported release lines once 1.0 is out.

| Version | Supported |
|---|---|
| latest `1.0.0-alpha` release | yes |
| older alphas | no, upgrade |

## Disclosure

1. We acknowledge a report within 3 working days, and give an initial assessment (confirmed or not, severity) within 10.
2. The fix is developed in a private fork or a draft GitHub security advisory, with a regression test, and for parser bugs a fuzz corpus entry under `fuzz/corpus/`.
3. We release, then publish the advisory (a GitHub Security Advisory, with a CVE requested through GitHub when warranted) and a CHANGELOG entry. Reporters are credited unless they ask otherwise.
4. The default embargo is 90 days from the report or 7 days after a fix is released, whichever comes first. Issues exploited in the wild may be published sooner. Embargoes set by an upstream project (quiche, BoringSSL, the JDK) are respected.

## Scope

In scope:

- Everything in this repository that ships in the jars: the Java core (`src/java`), the Clojure API (`src/clj`) and the JNI shim (`native/enso_quiche`).
- The native code bundled in the classifier jars. The shim statically links [quiche](https://github.com/cloudflare/quiche) (the release pinned in `native/enso_quiche/pins.env`), the BoringSSL it vendors through the `boring-sys` crate, and the Rust crates locked in `native/enso_quiche/quiche-Cargo.lock`. A vulnerability in those that is reachable through enso's HTTP/3 listener is in scope here; please also report it upstream (<https://github.com/cloudflare/quiche/security> for quiche, Google for BoringSSL).
- Protocol-level denial of service beyond what the documented limits allow (see [doc/options.md](doc/options.md#limits)): resource exhaustion from a small amount of traffic, request smuggling, header injection, response splitting, crashes or hangs on malformed input.

Out of scope:

- The JDK itself, including TLS for HTTP/1.1 and HTTP/2, which is the JDK's `SSLEngine`. Report those to the JDK vendor.
- Application handlers, and configurations that disable or raise the documented limits.
- Test, benchmark and CI tooling (`test/`, `bench/`, `fuzz/`, `script/`), unless it affects a published artifact.

## Native dependency advisories

Users can't patch the native code in the classifier jars themselves, so
advisories against it are handled like enso bugs.

Detection: the nightly workflow runs `cargo audit` against
`native/enso_quiche/quiche-Cargo.lock` (RustSec advisory database) and
fails on any advisory. Dependabot watches the GitHub Actions in use.
quiche and BoringSSL security releases are also tracked by hand, through
quiche's release notes and GitHub advisories, and through the `boring`
crate for BoringSSL.

Triage: decide whether the vulnerable code is reachable from enso. For
example, quiche's HTTP/3 module isn't used, since enso implements HTTP/3
and QPACK in Java, and BoringSSL is only used for the QUIC handshake.
Unreachable advisories are still fixed in the next regular release.

Fix, following "Bumping quiche or the toolchain" in
[doc/build.md](doc/build.md#bumping-quiche-or-the-toolchain):

1. Bump `native/enso_quiche/pins.env` (`QUICHE_VERSION`, `QUICHE_COMMIT`, and `RUST_TOOLCHAIN` if needed) and `Quiche.QUICHE_VERSION`. For an advisory in a dependency crate only, update that crate in `native/enso_quiche/quiche-Cargo.lock` instead (`cargo update -p <crate> --precise <version>` in a quiche checkout).
2. Regenerate `THIRD-PARTY-NOTICES`, and `NOTICE` if the vendored BoringSSL changed.
3. Let the test workflow pass (it rebuilds the shim from the new pins and runs every namespace, the sanitizer job and h3spec) and check that `cargo audit` is clean.
4. Release with `clojure -T:build release` (see [doc/build.md](doc/build.md#release-ci)). The release workflow rebuilds all five shims from the pins, checks and load-tests each, and publishes the core and classifier jars.
5. Publish the advisory, naming the upstream identifier (CVE or RUSTSEC) and the fixed enso version.
