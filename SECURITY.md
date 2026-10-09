<!-- ABOUTME: Security policy: how to report a vulnerability, supported versions, disclosure timeline, scope -->
<!-- ABOUTME: (including the bundled quiche/BoringSSL shim) and the advisory response process for native code. -->
# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

- Preferred: GitHub private vulnerability reporting, "Report a
  vulnerability" under the repository's Security tab
  (<https://github.com/mpenet/enso/security/advisories/new>).

Please include the enso version (or commit), JDK version and platform,
the protocol involved (HTTP/1.1, HTTP/2 over TLS or h2c, HTTP/3,
WebSocket), the server options in use, and a reproducer (a byte sequence,
a client command line or a test). Proof-of-concept traffic against
servers you do not own is out of bounds.

## Supported versions

enso is pre-1.0 (`1.0.0-alphaN`). Only the latest published release
receives security fixes; a fix ships as the next release. Once 1.0 is
released this section will list the supported release lines.

| Version | Supported |
|---|---|
| latest `1.0.0-alpha` release | yes |
| older alphas | no: upgrade |

## Disclosure policy

Coordinated disclosure:

1. Acknowledgement within 3 working days, initial assessment (confirmed or
   not, severity) within 10.
2. A fix is developed in a private fork or a GitHub security advisory
   draft, with a regression test (and, for parser bugs, a fuzz corpus
   entry under `fuzz/corpus/`).
3. Release, then publication of the advisory (GitHub Security Advisory,
   with a CVE requested through GitHub when the issue warrants one) and a
   CHANGELOG entry. The reporter is credited unless they ask otherwise.
4. Default embargo: 90 days from the report, or 7 days after a fix is
   released, whichever comes first. Issues exploited in the wild may be
   published sooner. An embargo set by an upstream project (quiche,
   BoringSSL, the JDK) is respected.

## Scope

In scope:

- Everything in this repository that ships in the jars: the Java core
  (`src/java`), the Clojure API (`src/clj`), and the JNI shim
  (`native/enso_quiche`).
- The bundled native code in the per-platform classifier jars: the shim
  statically links [quiche](https://github.com/cloudflare/quiche) (the
  release pinned in `native/enso_quiche/pins.env`) and the BoringSSL it
  vendors through the `boring-sys` crate, plus the Rust crates locked in
  `native/enso_quiche/quiche-Cargo.lock`. A vulnerability in those that is
  reachable through enso's HTTP/3 listener is in scope here; please also
  report it upstream (Cloudflare for quiche:
  <https://github.com/cloudflare/quiche/security>, Google for BoringSSL).
- Protocol-level denial of service beyond what the documented limits
  allow (see `doc/options.md#limits`): resource exhaustion with a small
  amount of attacker traffic, request smuggling, header injection,
  response splitting, crashes or hangs on malformed input.

Out of scope:

- The JDK itself (TLS for HTTP/1.1 and HTTP/2 is the JDK's `SSLEngine`):
  report to the JDK vendor.
- Application handlers, and configurations that disable or raise the
  documented limits.
- Test, benchmark and CI tooling (`test/`, `bench/`, `fuzz/`, `script/`)
  unless it affects a published artifact.

## Native dependency advisories

The classifier jars contain native code that enso users cannot patch
themselves, so advisories against it are handled like enso bugs:

- Detection: the nightly workflow runs `cargo audit` against
  `native/enso_quiche/quiche-Cargo.lock` (RustSec advisory database) and
  fails on any advisory; Dependabot watches the GitHub Actions in use.
  quiche and BoringSSL security releases are also tracked by hand (quiche
  release notes / GitHub advisories; BoringSSL through the `boring` crate).
- Triage: decide whether the vulnerable code is reachable from enso (for
  example, quiche's HTTP/3 module is not used: enso implements HTTP/3 and
  QPACK in Java; BoringSSL is used for the QUIC handshake only).
  Unreachable advisories are still fixed in the next regular release.
- Fix, following "Bumping quiche or the toolchain" in `doc/build.md`:
  1. bump `native/enso_quiche/pins.env` (`QUICHE_VERSION`,
     `QUICHE_COMMIT`, `RUST_TOOLCHAIN` if required) and
     `Quiche.QUICHE_VERSION`, or, for an advisory in a dependency crate
     only, update that crate in `native/enso_quiche/quiche-Cargo.lock`
     (`cargo update -p <crate> --precise <version>` in a quiche checkout);
  2. regenerate `THIRD-PARTY-NOTICES` (and `NOTICE` if the vendored
     BoringSSL changed);
  3. let the test workflow pass (it rebuilds the shim from the new pins,
     runs every namespace, the sanitizer job and h3spec) and check
     `cargo audit` is clean;
  4. release (`clojure -T:build release`, see `doc/build.md#release-ci`):
     the release workflow rebuilds all five shims from the pins, checks
     and load-tests each, and publishes the core and classifier jars;
  5. publish the advisory naming the upstream identifier (CVE / RUSTSEC)
     and the fixed enso version.
