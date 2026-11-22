# Security Model & Responsible Use

This is a local defensive triage and awareness lab, not a credential collection or impersonation platform.

## Scope and safeguards
- URL inputs are parsed heuristically; the app does not fetch submitted destinations.
- Awareness events are click-only and must not collect passwords, OTPs, tokens, or personal data.
- The server binds to loopback by default. Do not expose it to the public Internet.
- Reports may contain sensitive URLs or message content. Store and share them carefully.
- Header authentication hints are supplied by the pasted message and are not independently validated.
- IOC extraction is syntactic, not live reputation or attribution.

## Safe handling
Run in a disposable/local environment. Keep dependencies updated. Do not paste real private messages unless you have permission and have redacted sensitive content. Use the tool only for authorized defensive analysis and awareness training.

## Reporting
Please report bugs without attaching live credentials, secrets, or private data. Provide a sanitized reproduction.
