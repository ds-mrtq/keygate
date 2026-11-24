# Plan: a stranger installs and uses KeyGate in 10 minutes

Status: **proposed, waiting for the owner's approval on this PR.** No build work starts before that.

Outcome owned: *KeyGate that a stranger can install and use on Linux and Windows in 10 minutes,
with weekly releases that ship checksums.*

## 1. What "done" means

**The stranger.** A developer who has never seen KeyGate, reads English, and has a clean
Ubuntu 24.04 or Windows 11 machine (x86-64) with no Go toolchain, no clone of this repo and no
Cloudflare account. They follow only `README.md`.

**The stopwatch.** Starts when the README is opened. Stops when all of these have happened:

1. a release archive is downloaded and its SHA-256 matches `SHA256SUMS`;
2. `kg version` prints the release tag;
3. a vault exists (`kg init`) and the broker is running and unlocked;
4. a demo secret is stored, a policy is applied, and `kg run` prints the output of a demo
   command with the value replaced by `[kg:demo/token]`;
5. `kg audit show` lists that run.

**Done criteria** (all must hold, each with a link to the evidence):

| # | Criterion | Evidence |
|---|---|---|
| D1 | The stopwatch run takes 10:00 or less on clean Linux, three runs in a row | Timing log with per-step times (sub-task 8) |
| D2 | The same on clean Windows 11 | Timing log; the approval step needs real Windows Hello, see "What cannot be checked by a session" |
| D3 | CI runs build, vet and tests on Linux and Windows for every PR, both required | Green runs of the matrix on `main` |
| D4 | A release is published every week without anybody pushing a tag, with archives for Linux and Windows (amd64, arm64) and `SHA256SUMS` | Two scheduled releases one week apart on the Releases page |
| D5 | Every published release is re-downloaded by CI on Linux and Windows, checksums verified, and `kg version` equals the tag | Green "verify release" job on each release |
| D6 | A tampered archive is refused by the install scripts | CI negative test |
| D7 | `README.md` and `README.vi.md` describe the same install and first-run steps | Review in the docs PR |

## 2. Where the repo stands today (read and tried on 2026-11-24, commit `e3072af`)

Observed directly, on a Linux machine with a production (non-`kgtest`) build:

- **No release exists.** `release.yml` builds six archives plus `SHA256SUMS` and attestations, but
  only on a pushed `v*` tag, and it leaves a *draft* that has to be published by hand. There are no
  tags and no releases yet. Nothing is scheduled.
- **The README quick start is build-from-source** (`go build`, Go 1.26) and its example is an
  Oracle wallet with a Windows path. There are no download, verify or PATH steps.
- **A Linux-only user cannot get past `kg policy apply`.** Linux has no user-presence approver, so
  the broker falls back to "approve from another device": it prints a challenge and waits for a
  signature made by `kg approve` on a *different* key-holder device (`approve.Verify` rejects the
  broker's own device). `kg approve` on Linux then fails with "this OS has no user-presence". So a
  person with one Linux machine, or with Linux machines only, needs a Windows or macOS device or a
  phone paired through their own Cloudflare Worker before the first `kg run`. This is the main
  blocker for the Linux half of the outcome and needs an owner decision (Q1).
- **No `kg version`.** `kg version` and `kg --version` print "unknown command". The binary carries
  no version, so an install cannot be checked against a tag.
- **All CLI output is Vietnamese** (usage, prompts, the approval review text, errors), while the
  README is English. `docs/CLI.md`, `docs/DESIGN.md`, `integrations/README.md` and the user guide
  are Vietnamese too (Q3).
- **CI runs on `ubuntu-latest` only.** Windows and macOS get `go vet` by cross-compilation; no test
  runs on Windows, the platform the project is used on daily.
- `kg init`, `kg broker`, unlock with the device password, and `kg status` worked first time on
  Linux in about a minute.

Not verified from here (no Windows machine in the planning session):

- What a Windows user without Windows Hello set up (no PIN, a VM) sees on the first approval. The
  code returns "user has not confirmed (`<result>`)" for anything other than `Verified`.
- Whether the Go tests pass on a GitHub Windows runner. The environment notes say they need a long
  `TMP`/`TEMP` path.
- SmartScreen behaviour for the unsigned `kg.exe` / `kgw.exe`.

## 3. Decisions for the owner

Approving this PR approves the recommended option of each. Write a different choice in a PR
comment and the plan is updated before work starts.

| # | Question | Recommended | Alternatives |
|---|---|---|---|
| Q1 | How does a single Linux machine approve? | Where the OS has no user-presence, a `user-presence` approval is answered by typing the **device unlock password at the broker's own terminal** (the same gate that already unlocks the vault; an agent cannot type there). `approval: device` keeps its meaning: another device must sign. | (b) Keep today's behaviour and require a second Windows/macOS device or a phone: Linux cannot meet 10 minutes. (c) Something else you prefer. |
| Q2 | Are weekly releases published automatically? | Yes: the scheduled run publishes a normal (non-draft) release, skipped when nothing changed since the last tag. Manual `v*` tags keep working. | Keep drafts; then "weekly" depends on a manual click each week. |
| Q3 | CLI language for a stranger | Keep the CLI in Vietnamese for this outcome; the quick start shows each prompt the user will meet with an English gloss. English CLI output is a follow-up outcome. | Add English CLI messages now (large: many tests assert the Vietnamese strings). If the stopwatch runs show the glosses are not enough, this comes back to you. |
| Q4 | Version numbers | First release `v0.1.0`; each weekly release bumps the patch (`v0.1.1`, …). You push a tag by hand for a minor or major bump. | Date-based tags (`v2026.48`). |
| Q5 | Schedule | Mondays 02:00 UTC (09:00 +07). | Any other slot. |
| Q6 | Convenience installers | Add `install.sh` and `install.ps1` that download, verify the checksum and install to a per-user directory; the README also shows the manual steps, which stay the reference. | Manual steps only. |

Not proposed, because the limits rule them out: Authenticode or Apple signing (needs new secrets),
package managers such as winget, Homebrew or apt repositories (need new accounts or repositories),
any change to the Cloudflare relay.

## 4. Sub-tasks, in order

Rules for every sub-task: its own session in Normal mode, one PR, never merged by the session;
only one of these PRs open at a time; the PR description carries the proof (command output or the
CI run link); a real bug found on the way gets its own failing-test-first PR; no new Go
dependency (stdlib, `x/crypto`, `x/sys` only); no real secret anywhere, the demo secret is a fake
value. Pushes go only to PR branches on `ds-mrtq/keygate`.

### 1. CI on Linux and Windows

- **Change:** turn the `go` job in `ci.yml` into a matrix over `ubuntu-latest` and
  `windows-latest` running build, vet and `go test -count=1 -tags kgtest ./...` (race on Linux),
  with a long `TMP`/`TEMP` on Windows. Fix or, with a written reason, skip tests that fail only
  because of the runner. macOS stays vet-only (outside this outcome).
- **Self-check:** both matrix legs green on the PR; a deliberately broken assertion pushed to a
  scratch commit turns the Windows leg red (shown in the description, then removed).
- **Done when:** both legs are green and the description lists every test that needed a change and
  why.

### 2. `kg version`

- **Change:** `kg version` and `kg --version` print the version, commit and OS/arch. The value
  comes from `-ldflags -X` in `release.yml`; a plain `go build` prints `dev`. Documented in
  `docs/CLI.md`.
- **Self-check:** unit test for the command; the release workflow's PR dry run (it already triggers
  on changes to `release.yml`) gains a step that unpacks the Linux archive and the Windows zip on
  matching runners and asserts the printed version equals the package version.
- **Done when:** the dry-run artifacts on Linux and Windows print the expected version in CI.

### 3. Single-machine approval on Linux (depends on Q1)

- **Change:** first a failing test: one Linux device, production approver, `kg policy apply`
  followed by `kg run` must succeed with input from the broker's terminal only. Then the change
  chosen in Q1. With the recommended option: a wrong password is refused and counted, the prompt
  shows the same review text as today, the audit line records how it was approved, and
  `approval: device` is untouched. `docs/CLI.md`, `docs/DESIGN.md` and both READMEs' security
  sections are updated in the same PR.
- **Self-check:** the new tests fail on `main` and pass on the branch (both outputs in the
  description); tests that an agent-side client cannot supply the password over the socket and
  that `approval: device` still rejects the broker's own device; a manual run with a production
  build on a clean Linux machine, transcript in the description (fake secret).
- **Done when:** the Linux stopwatch steps 3 to 5 complete on one machine with no other device.

### 4. Windows first run

- **Change:** on a Windows machine, walk the first run with a production build: `kg init`,
  `kgw tray`, first approval with Windows Hello available and not available, and the SmartScreen
  prompt. Fix what blocks a stranger without changing the security model: an actionable message
  when Hello is not set up (what to enable and where), and anything else found. Each real bug gets
  its own failing-test-first PR.
- **Self-check:** before/after screenshots or transcripts from the Windows machine; unit tests for
  the message mapping using the existing verifier `Command` override.
- **Done when:** every dialog and message a new Windows user meets up to the first `kg run` is
  listed in the PR, and none is a dead end.
- **Limit:** a session's Windows machine most likely has no Hello hardware or PIN. Whatever cannot
  be exercised there is listed as "not verified" and goes to the owner's run in sub-task 8.

### 5. Install scripts with checksum verification (depends on Q6, after 2)

- **Change:** `install.sh` (Linux: amd64/arm64, installs `kg` to `~/.local/bin`) and `install.ps1`
  (Windows: installs `kg.exe` and `kgw.exe` to `%LOCALAPPDATA%\Programs\KeyGate`, adds it to the
  user PATH). Both resolve the latest release or take a version, download the archive and
  `SHA256SUMS`, refuse to install on a mismatch, and print how to verify the attestation with
  `gh`. No `sudo`, no admin rights. A base-URL override lets CI point them at a local directory.
- **Self-check:** `shellcheck` and PSScriptAnalyzer; a CI job on `ubuntu-latest` and
  `windows-latest` installs from the dry-run packages, then runs `kg version`; a negative test
  flips one byte of the archive and requires a non-zero exit and no installed file (D6); the Linux
  leg also runs inside a bare `ubuntu:24.04` container to prove nothing but `curl`/`tar`/
  `sha256sum` is needed.
- **Done when:** positive and negative jobs are green on both systems.

### 6. Weekly published releases (depends on Q2, Q4, Q5; after 2)

- **Change:** `release.yml` gains a `schedule` trigger. The scheduled run finds the last tag,
  stops if `main` has no new commits, otherwise computes the next version, builds and packages as
  today, and creates the tag and the published release in one step with the workflow's own token
  (no new secret; a tag pushed by a workflow would not start a second workflow, so it must be one
  run). Release notes list the merged PRs and the verify commands. A final `verify-release` job
  downloads the published assets on Linux and Windows, checks `SHA256SUMS` (`sha256sum -c`,
  `Get-FileHash`), runs `gh attestation verify`, and checks `kg version` equals the tag. A failed
  verification marks the release as failed in its notes and fails the run. `docs/RELEASE.md` is
  rewritten to match.
- **Self-check:** `actionlint`; the PR dry run exercises version computation ("next version
  would be vX"), packaging and the verify job against the dry-run packages without creating a tag
  or release; the skip path is shown with a run where nothing changed.
- **Done when:** the dry run is green. The first real release needs the owner: after merge, start
  the workflow once from the Actions page (or wait for the first scheduled run). Sessions do not
  push tags.

### 7. Quick start rewrite (after 3, 4, 5, 6 and the first release)

- **Change:** `README.md` and `README.vi.md` get the same quick start: install on Linux and on
  Windows (script and manual steps with checksum verification), then one first-run walkthrough
  with a generic env-secret and a tiny hash-pinned demo script (no Oracle, no relay, no phone),
  each prompt shown with what to type, ending at the masked output and the audit line. Building
  from source, Oracle wallets, phone approvals and agent integration move below it. The archive's
  packaged README follows automatically.
- **Self-check:** a CI job runs the documented Linux commands, copied from the README by a script
  so the two cannot drift, with the production binary under a pseudo-terminal in a bare
  `ubuntu:24.04` container and asserts the masked output and the audit entry; on
  `windows-latest` it runs every documented command up to the first step that needs Windows Hello.
  Links checked. EN and VI compared step by step in the description.
- **Done when:** the Linux quick-start job is green end to end and the Windows job is green up to
  the Hello step.

### 8. Stopwatch runs on clean machines

- **Change:** none planned; this sub-task measures. A fresh Linux session and a fresh Windows
  session (machines with no Go and no clone) open only the README of the published release and
  follow it by hand, recording wall-clock time per step and every hesitation or error. Anything
  over budget or confusing becomes a fix PR (docs, or its own failing-test-first PR for a bug),
  and the run is repeated from a clean machine until three Linux runs in a row are at or under
  10:00. The PR adds the timing log to this file's "Results" section.
- **Budget used to judge each step:** download, verify, install 2:00; `kg init` 2:00; broker,
  secret, policy 3:00; first `kg run` and audit 2:00; slack 1:00.
- **Self-check:** screen recording of one full Linux run and one Windows run; checksum
  verification shown in the recording; the published release used is named by tag.
- **Done when:** D1 holds with evidence, D2 holds for everything a session can exercise, and the
  owner has the short list below for his own machine.

## 5. What cannot be checked by a session

- **Windows Hello approval on real hardware.** CI runners and session machines have no biometric
  or PIN enrolment. The Windows run in sub-task 8 will be complete only up to the first Hello
  prompt unless the machine allows a PIN. Final sign-off of D2 needs one 10-minute run by the
  owner (or anyone) on a real Windows 11 laptop; the session prepares the exact steps and a
  timing sheet.
- **A truly naive reader.** Sessions know the project. To reduce the bias, the stopwatch session
  gets only the README URL and the definition of "stopwatch" above, not this plan or the repo
  history.
- **Two releases one week apart (D4)** can only be shown after two weeks have passed; the session
  that finishes sub-task 8 reports the first one, and the second is checked the following week.

## 6. Out of scope

macOS install path and tests on macOS, native code signing, package managers, the phone/relay
flow, English CLI output (unless Q3 is answered differently), any change to the relay deployment.

## Results

(Filled in by sub-task 8.)
