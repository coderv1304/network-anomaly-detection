# Archived legacy dashboard

These files were the stored-flow dashboard served at `/dashboard` before P0.

- `dashboard.html` — legacy template, superseded by `templates/console.html`.
- `dashboard.css` — stylesheet for the legacy template.
- `dashboard.js` — client script for the legacy template.

They are archived, not deleted, so the prior surface remains inspectable. They are not loaded by any served route. `/dashboard` now permanently redirects to `/` with HTTP 301.

Do not re-serve these files without re-auditing every claim against `docs/CLAIM_EVIDENCE_MATRIX.md`.
