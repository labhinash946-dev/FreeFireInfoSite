# Account configuration

## Where credentials come from

Service accounts (the guest logins the app uses to query Free Fire, not the player UID being searched) are **not** stored in this repository. Provide them in one of these ways, in order of precedence:

1. Complete exact-region environment override: `FREEFIRE_<REGION>_UID` and `FREEFIRE_<REGION>_PASSWORD`.
2. Complete group environment override (`AMERICAS` or `GLOBAL`, where applicable).
3. `FREEFIRE_ACCOUNTS` environment variable holding `UID PASSWORD REGION` rows (recommended on a host such as Render).
4. A local `accounts.txt` in the same format. It is git-ignored and meant for local development only.

Within sources 3 and 4, exact-region rows take precedence over group rows. If `FREEFIRE_ACCOUNTS` is set, `accounts.txt` is not read.

## Format

```text
# UID PASSWORD REGION
1234567890 example-password IND
2345678901 example-password BR
3456789012 example-password GLOBAL
```

See `accounts.example.txt`. Whitespace separates columns; empty lines and lines starting with `#` are ignored. On hosts that only accept a single-line value, a literal `\n` can separate rows.

Supported scopes: IND, BR, VN, ID, TH, TW, GLOBAL (and AMERICAS).

- BR is the fallback for BR/US/NA/SAC/EUROPE (EU aliases EUROPE).
- GLOBAL serves BD/SG/ME/PK/CIS/RU.
- An AMERICAS row, if deliberately configured, takes precedence over BR for other Americas regions.

Missing or incomplete credentials fail explicitly with `CREDENTIAL_CONFIG_ERROR`, without exposing any value. No values from different pairs are mixed. Restart the process after replacing a pair to discard cached tokens.

## Keeping secrets out of git

`accounts.txt`, `accounts-legacy.txt` and `.private/` are in `.gitignore`. Never paste real passwords into issues, docs, logs or commits. If credentials were ever committed, removing the file is not enough: they remain in git history, so make the repository private or rewrite history, and replace the accounts.

## Local run

```powershell
python -m pip install -r requirements.txt
python -m flask --app app run --host 127.0.0.1 --port 5055 --no-debugger --no-reload
python tools/diagnose.py --regions BR VN
```

The Windows helper `tools/start-local.ps1` can load encrypted local overrides with `-UsePrivateCredentials`. Environment variables supplied by the host still take precedence.

Shared guest accounts can become unavailable independently of the code. Diagnose OAuth, MajorLogin and player lookup separately before changing protocol values. Never label an unrecognized error response as a confirmed ban or queue without evidence. `python tools/diagnose.py --regions IND BR VN ID TH TW BD --self-lookup` prints status and response sections without account IDs, passwords, tokens or raw player data.
