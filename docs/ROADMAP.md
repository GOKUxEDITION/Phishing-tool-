# Defensive Suite Roadmap

- [x] Offline URL heuristic review
- [x] Batch URL parsing
- [x] Email header and attachment-name triage
- [x] IOC text extraction
- [x] Click-only awareness demo
- [x] Local SQLite event log and CSV/JSON export
- [ ] Reputation API integration (explicit opt-in, keys stored locally, no URL visiting)
- [ ] File metadata/hash inspection (never execute files)
- [ ] HTML/PDF case report generation
- [ ] Filters, pagination, and event-log retention controls
- [ ] Expanded property-based and fuzz tests
- [ ] Dependency audit automation

Features that collect credentials, OTPs, session tokens, or imitate real sign-in pages are out of scope.
