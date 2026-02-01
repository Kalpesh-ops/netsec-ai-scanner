# Contributing

Thank you for your interest in improving NetSec AI Scanner. This project is security-focused and welcomes high-quality contributions.

## Branching Strategy

- `main` is always deployable.
- Create feature branches from `main` using the pattern `feature/<short-name>`.
- Use `fix/<short-name>` for bug fixes and `docs/<short-name>` for documentation updates.
- Open a Pull Request (PR) targeting `main`.
- Keep PRs focused; avoid mixing unrelated changes.

## How to Report Bugs

Please open a bug report using the issue template.

Include:
- Clear reproduction steps
- Expected vs. actual behavior
- Logs or screenshots (redact sensitive data)
- OS and environment details

If the issue is security-related, do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).

## Local Testing Requirements

Before submitting a PR, verify the following:

### Backend
- Python 3.10+ installed
- Nmap installed and available in PATH
- Create `.env` from `backend/.env.example`
- Start the API: `python server.py`
- Run a smoke test: `curl http://localhost:8000/health`

### Frontend
- Node.js 20+ installed
- Create `frontend/.env` from `frontend/.env.example`
- Install dependencies: `npm install`
- Start dev server: `npm run dev`
- Optional lint: `npm run lint`

## Code Style

- Keep changes minimal and well-scoped.
- Prefer clear, explicit naming over brevity.
- Avoid committing generated files, secrets, or local artifacts.
