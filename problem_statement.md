# Ghost Data Still Exists

Build an AI-powered deletion audit agent that proves whether a user's personal data is truly gone.

A user deletes an old account. A few days later, they try to use the same email address again and the platform responds: **“This email is already registered.”**

The primary account is no longer visible, and the deletion workflow says **“Complete.”** However, the email may still exist in a secondary database, support attachment, search index, analytics export, log, archive, or backup. A synchronization or restore process may also recreate information after it was deleted.

The agent must investigate the supplied records, determine the user's current and historical identifiers, reconstruct what happened across systems, and decide whether the deletion is actually complete.

When data remains, the agent must produce the ordered remediation steps required to remove, redact, or anonymize it. When deletion has already been completed, the agent must produce the checks that prove it. The agent must also preserve records that the supplied policy requires the organization to retain.

## What You Need to Build

For each deletion request, build a system that determines:

- whether the deletion is `COMPLETE` or `INCOMPLETE`;
- which records or identifiers still expose the user;
- which active processes can recreate deleted data;
- the ordered remediation steps required to complete the request.

A deletion is complete only when:

- every relevant copy has received the treatment required by `deletion_rules.csv`;
- no active sync, import, or restore path can recreate the data;
- retained records contain only the identifiers permitted by the rules; and
- records that must be retained remain available.

## Files Provided

All participant-facing files are inside `dataset/`.

Only `dataset/deletion_requests.csv` requires answers. The other files provide context:

1. `dataset/deletion_requests.csv` - Deletion requests that must be audited.
2. `dataset/sample_deletion_requests.csv` - Example deletion requests.
3. `dataset/sample_output.csv` - Completed canonical answers for the sample requests.
4. `dataset/user_identities.csv` - One current identity row for each user.
5. `dataset/user_audit_log.csv` - Historical changes to users' names, email addresses, phone numbers, and other identifiers.
6. `dataset/system_activity.csv` - Operations reported by services, workers, syncs, exports, backups, and restore processes.
7. `dataset/deletion_rules.csv` - Rules defining whether each category of data must be deleted, redacted, anonymized, or retained.
8. `dataset/evidence_files.csv` - Global manifest of the supplied PDFs, images, logs, SQLite snapshots, JSON records, emails, and text files.
9. `dataset/output.csv` - Blank submission template. Fill this file with answers for `deletion_requests.csv`.

Evidence files are stored under `dataset/evidence/`. For example:

```text
dataset/evidence/documents/<file_id>.pdf
dataset/evidence/images/<file_id>.png
dataset/evidence/logs/<file_id>.log
dataset/evidence/databases/<file_id>.sqlite
```

Use the supplied identity, activity, evidence, and timestamp data to determine the deletion state at `audit_at`. Activity and evidence records are global and may include unrelated users and files. Ignore evidence produced after `audit_at`.


