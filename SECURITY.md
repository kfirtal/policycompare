# Security and publication notes

Use only on systems you are authorized to access. Collection is read-only with respect to firewall policy and requires explicit connection authorization.

- Never commit credentials, raw API responses, live snapshots, policy exports, customer identifiers, or operational logs.
- Real output belongs in ignored `reports/` and `snapshots/` trees, outside public examples.
- Keep TLS verification enabled; supply trusted CA bundles when needed.
- Ignore rules do not remove committed data. Review branches, tags, history, archives, releases, and attachments before publication.
- If a real credential is exposed, revoke or rotate it first. Removing it from the latest file is insufficient.
- Use synthetic reproductions in public issues; never paste secrets or internal data.

Portfolio review used heuristics and manual inspection of flagged content. It cannot guarantee discovery of every sensitive value. It does not establish live compatibility or organizational release approval.
