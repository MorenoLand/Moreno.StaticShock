# Security policy

## Supported versions

The `master` branch is the supported version. Generated artifacts and forks are not supported by
this project; report issues in the code that produces them.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Include the affected file, the impact, a minimal reproduction and the commit hash.

If private reporting is unavailable, contact the maintainer through GitHub and say that you have a
security report. Do not include exploit details in a public message.

## Scope

In scope:

- the pipeline scripts in `pipeline/`
- the runtime in `runtime/`
- the build system and generated host layout
- path handling, file writes and process/job ownership
- evidence and records that could be forged or misread as verified

Out of scope:

- the original application or its third-party DLLs
- the operating system, drivers or anti-cheat
- content produced by a user's build that is not part of this repository

## Safe harbour

Good-faith research on this repository is welcome. Do not access other people's systems, do not
distribute malware, and do not publish an exploit before the maintainer has had a reasonable chance
to respond.

## Response

This is a volunteer project. Reports are acknowledged on a best-effort basis. A fix is released on
`master` with a short note; a report may be closed as not reproducible, out of scope, or a duplicate.

## No secrets in reports

Do not attach an original executable, a game asset, a key or personal data. A digest, a stack
trace, a small synthetic reproduction and the exact commands are enough.
