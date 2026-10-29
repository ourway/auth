# 47. Expired API keys stop counting toward the 25-key cap

Ticket: issuedb #47. Release: 3.7.2.

## EARS spec

- When a user's API key passes its expires_at, the auth service shall stop counting that key toward the 25-active-keys-per-user cap.
- While a user holds 25 keys that are neither revoked nor expired, the auth service shall refuse a further key with 400.
- When a user holds 25 unrevoked keys and at least one has passed its expires_at, the auth service shall mint a new key.
- The auth service shall leave is_active, revoked_at and the listing shape of an expired key unchanged.
- The expiry boundary for the cap shall be the same as for validate: a key whose expires_at equals now counts as expired.

## Synthesis

Technical problem: admission control counts a resource that no longer grants anything.

Solution domain: a localised change to the admission query in `create_api_key`, using the predicate validate already applies (`expires_at <= now` is expired). No new component or dependency.

Alternatives:

| Option | Decision | Reason |
|---|---|---|
| Exclude expired keys in the count | Chosen | One query change, no state written, same boundary as validate |
| Revoke expired keys automatically, on read or by a sweeper | Rejected | Writes state the owner did not ask for, changes `is_active` and `revoked_at` that consumers render, and needs a scheduler |
| Leave it and document it | Rejected | Consumers who set an expiry get refused by keys nobody can use. Vellum had to build its own sweep |

## Background

Found on 2026-10-27 while answering Vellum's S5 question, and proved live against auth.rodmena.com 3.7.1: with 24 live keys and 1 expired one, a mint answered 400 until the expired key was revoked.
