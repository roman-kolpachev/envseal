# Security policy

## Supported versions

envseal is before 1.0. Security fixes go into the latest release only. Please update to it before you report a problem.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Report it privately on GitHub: [Security > Report a vulnerability](https://github.com/roman-kolpachev/envseal/security/advisories/new). Only the maintainer sees the report.

Helpful details:

- the envseal version (`envseal version`) and your OS;
- what an attacker needs: local access, a crafted `.env` file, a crafted vault, a crafted environment;
- the steps to reproduce, or a proof of concept;
- what the attacker gains: a secret read, a command run, a file written.

## What happens next

- You get a first answer within 7 days.
- We agree on the severity and a fix. We aim to ship a fixed release within 30 days of a confirmed report, sooner for high and critical issues.
- The fix is published as a GitHub security advisory, with a CVE when the issue qualifies, and noted in the release notes.
- You are credited in the advisory, unless you ask not to be.

## Scope

envseal protects secrets at rest: in the vault files you commit to git. It cannot protect a secret from:

- someone who holds a private key with access to that secret;
- the process you start with `envseal run`, and anything that can read that process's environment or its sealed file;
- a machine that is already compromised.

Reports about these are still welcome when envseal makes them worse than they need to be, for example by leaking a secret to a place the user did not ask for.
