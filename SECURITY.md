# Security Notes

This project analyzes email content and can optionally remember Gmail login data on the local machine. Treat the repository and runtime data carefully.

## Do not commit

- Gmail App Passwords.
- `.env` or any local secret file.
- `backend/saved_login.db`.
- `backend/saved_login.key`.
- Local virtual environments such as `.venv/`.
- Browser extension package artifacts such as `.crx`, `.pem` and zip exports.

## Local saved login

When `remember_login` is enabled, the backend stores credentials in local runtime files under `backend/`. These files are ignored by Git, but they still exist on the developer machine until deleted through the extension or `DELETE /api/saved-login`.

## Recommended usage

- Use a dedicated Gmail App Password for testing.
- Revoke the App Password after demos or shared-machine usage.
- Keep the backend bound to `127.0.0.1` unless there is a deliberate reason to expose it.
- Review network-facing changes before deploying beyond local development.

## Scope

This is an educational and research-oriented phishing detection project. It should be hardened, reviewed and tested further before production use.
