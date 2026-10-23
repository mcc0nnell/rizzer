# Identity-sequence replay (experimental)

This is a **read-only, offline, synthetic-only** detection experiment alongside
Rizzer's native fuzzing engine. It does not extend the engine with network
access or supply a general agent framework.

## Motivation and source boundaries

Microsoft's October 21, 2026 Storm-0940 report describes ARTEX as a
multi-agent Go/Next.js penetration-testing framework that maintains a graph of
discovered assets and vulnerabilities. The observed ConnectWise-related
activity included app-only authentication, Microsoft Graph operations,
credential modification and privilege changes in downstream tenants.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/

**Separate campaigns matter:** Microsoft's 151,000-plus failed sign-ins and
2,900-per-minute peak refer to a password-spraying campaign. They should not be
treated as successful app-only authentication or evidence of exfiltration.
The report says successful sign-in alone does not establish data access.

This lab implements only a **correlation hypothesis** based on patterns in
that reporting. It is not an ARTEX implementation or a vendor detection.

## Run without credentials or network

From the repository root, on Python 3.11+:

```sh
python3 identity_replay.py \
  --input fixtures/identity-sequence.jsonl \
  --out /tmp/rizzer-identity-receipt-01
cat /tmp/rizzer-identity-receipt-01/receipt.json

python3 -m unittest -v test_identity_replay
```

The output directory must not exist. The tool never signs in to Microsoft
365, contacts endpoints, runs arbitrary commands, accesses a radio, or
modifies source events. It accepts only the explicitly passed local UTF-8
JSONL input.

## Event contract: `rizzer.identity-replay.v0`

Each JSONL line is one synthetic record with these **required** common keys:

- `ts`: UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`
- `event_id`: unique, nonempty event identifier
- `tenant`, `app`, `actor`: synthetic grouping identifiers
- `source`: synthetic observed origin identifier, not a trust verdict
- `kind`: exactly one of `app_signin`, `graph_activity`,
  `credential_added`, `role_grant`

Kind-specific fields:

| Kind | Extra required field(s) |
| --- | --- |
| `app_signin` | `result`: `success` or `failure` |
| `graph_activity` | `operation`: `directory_read`, `mail_read`, or `secret_read` |
| `credential_added` | `target`: synthetic identity ID |
| `role_grant` | `target` and `role`: synthetic identity ID and role name |

Extra keys and unknown event kinds are rejected, including password and
token fields. The CLI accepts no more than 1 MiB and 4,096 records, and the
correlation window is bounded to 1–3,600 seconds (900 seconds by default).

## Correlation semantics

For each credential or role change, find the most recent successful
`app_signin` by the **same tenant, application, and actor** no more than the
window earlier. Include any same-identity Graph events between the sign-in
and the change as corroborating context. Failed sign-ins never establish
this sequence. No event is correlated across tenants, apps, or actors,
and an event outside the window does not match.

A self-assigned Global Administrator or Privileged Role Administrator grant
is tagged `high`; all other matched changes are tagged `review`.
These are *triage priorities*, not proof of wrongdoing. No automatic
blocking, account changes, or vulnerability filing occurs.

Input lines may be reordered without changing the normalized SHA-256 input
digest or receipt. Evidence IDs and the observed source pair are preserved.
The receipt has **no signature**; the input hash is not a WindAnvil
attestation. A future adapter could send a receipt to an independently
reviewed WindAnvil verification path.

## Important limits

- This is not a live Entra/Graph telemetry connector, production SIEM,
  attribution engine, full graph database, LLM agent, or ARTEX replica.
- It does not prove compromise, data access, data theft, or alert coverage.
- Common identity identifiers in raw enterprise logs may require special
  mappings; **do not feed production log dumps or secrets to this lab**.
- The schema is deliberately narrow. Real graph APIs, role assignments,
  logging gaps, clocks, and consent behavior require separate validation.
- The underlying Rizzer fuzzing engine remains an independent native
  experiment with its existing test and privilege boundaries.
