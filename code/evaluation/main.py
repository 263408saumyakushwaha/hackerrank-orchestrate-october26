import csv
import json
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(ROOT, "dataset")
EVIDENCE_DIR = os.path.join(DATASET, "evidence")
OUTPUT = os.path.join(ROOT, "output.csv")

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}
DELETE_WORDS = (
    "delete", "deletion", "erase", "erased", "remove my data",
    "close my account", "close this account", "account-deletion",
    "account deletion", "permanent account"
)
EXTENSIONS = {".txt", ".log", ".json", ".sql", ".csv", ".xml", ".yaml", ".yml"}

def read_csv(name):
    path = os.path.join(DATASET, name)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def norm(value):
    return str(value or "").strip().lower()

def safe_text(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def find_email_fields(row):
    return [norm(v) for k, v in row.items() if "email" in norm(k) and norm(v)]

def build_identity_map(identities, audits, request_email):
    """Best-effort email -> user_id/current and historical identifiers map."""
    email_to_ids = defaultdict(set)
    email_to_terms = defaultdict(set)

    for row in identities:
        emails = find_email_fields(row)
        ids = [norm(v) for k, v in row.items()
               if ("user_id" in norm(k) or "identity_id" in norm(k)) and norm(v)]
        terms = {norm(v) for k, v in row.items()
                 if norm(v) and any(t in norm(k) for t in
                 ("email", "phone", "name", "user_id", "identity", "hash"))}
        for email in emails:
            email_to_ids[email].update(ids)
            email_to_terms[email].update(terms)

    # Audit rows are historical identifier changes; do not assume old_value is an email
    # unless it actually looks like one.
    for row in audits:
        user_id = norm(row.get("user_id"))
        for field in ("old_value", "new_value"):
            value = norm(row.get(field))
            if "@" in value and "." in value:
                email_to_ids[value].add(user_id)
                email_to_terms[value].add(value)
                if user_id:
                    email_to_terms[value].add(user_id)

    return email_to_ids, email_to_terms

def load_evidence_manifest():
    rows = read_csv("evidence_files.csv")
    manifest = []
    for r in rows:
        fid = (r.get("file_id") or "").strip()
        rel = (r.get("file_path") or "").strip().replace("/", os.sep)
        path = os.path.join(EVIDENCE_DIR, rel.replace("evidence" + os.sep, "", 1)) \
            if rel.startswith("evidence" + os.sep) else os.path.join(DATASET, rel)
        if not os.path.isfile(path):
            # Some manifests store paths relative to dataset/evidence.
            path = os.path.join(DATASET, rel)
        if not os.path.isfile(path):
            path = os.path.join(EVIDENCE_DIR, os.path.basename(rel))
        manifest.append({"evidence_id": fid, "path": path, "file_path": rel})
    return manifest

def category_from_path(path):
    p = norm(path)
    if "search" in p or "index" in p:
        return "SEARCH_INDEX_ENTRY", "search_service"
    if "support" in p or "attachment" in p or "message" in p:
        return "SUPPORT_MESSAGE", "support_platform"
    if "analytic" in p or "telemetry" in p:
        return "ANALYTICS_PROFILE", "analytics_platform"
    if "export" in p:
        return "USER_EXPORT", "export_service"
    if "market" in p:
        return "MARKETING_PROFILE", "marketing_service"
    if "email" in p or "delivery" in p:
        return "EMAIL_DELIVERY_LOG", "email_service"
    if "backup" in p or "archive" in p or "restore" in p:
        return "BACKUP_ARCHIVE", "backup_service"
    if "audit" in p or "security" in p:
        return "SECURITY_AUDIT_LOG", "security_service"
    if "cache" in p:
        return "CACHE_ENTRY", "cache_service"
    if "replica" in p or "database" in p or "customer_data" in p:
        return "USER_PROFILE", "account_service"
    if "account" in p or "profile" in p:
        return "USER_PROFILE", "account_service"
    return "USER_PROFILE", "account_service"

def infer_resource_ids(text, user_ids, email):
    """Extract plausible resource identifiers from evidence lines mentioning the subject."""
    found = set()
    lines = text.splitlines()
    needles = {norm(email)} | {norm(x) for x in user_ids if norm(x)}
    needles = {n for n in needles if n}
    id_pattern = re.compile(r"\b(?:account|profile|user|search|support|analytics|export|marketing|email|cache|audit|attachment|message|tombstone|backup|record|telemetry|event|customer)_[A-Za-z0-9-]+\b", re.I)
    for line in lines:
        low = norm(line)
        if any(n in low for n in needles):
            for match in id_pattern.findall(line):
                found.add(match)
            # SQL INSERT rows / JSON fragments may contain the user id but resource is implicit.
            for uid in user_ids:
                if norm(uid) and norm(uid) in low:
                    found.add(uid)
    return found

def evidence_for_subject(manifest, email, user_ids):
    hits = []
    for item in manifest:
        path = item["path"]
        if not os.path.isfile(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext not in EXTENSIONS:
            continue
        content = safe_text(path)
        resources = infer_resource_ids(content, user_ids, email)
        # Direct email or user-id mention is evidence. Do not treat filenames alone as proof.
        lower_content = norm(content)
        direct = norm(email) in lower_content or any(norm(uid) in lower_content for uid in user_ids if norm(uid))
        if direct:
            category, system = category_from_path(path)
            hits.append({
                "evidence_id": item["evidence_id"],
                "path": path,
                "category": category,
                "system": system,
                "resources": sorted(resources) or [default_resource(category, user_ids)],
                "content": content,
            })
    return hits

def default_resource(category, user_ids):
    if category == "USER_PROFILE":
        return "account_" + (user_ids[0].replace("user_", "") if user_ids and user_ids[0].startswith("user_") else "unknown")
    return category.lower() + "_unknown"

def activity_for_resources(activities, resources, user_ids):
    out = []
    targets = {norm(x) for x in resources}
    targets.update(norm(x) for x in user_ids)
    for row in activities:
        rid = norm(row.get("resource_id"))
        details = norm(row.get("details"))
        if rid in targets or any(t and t in details for t in targets):
            out.append(row)
    return out

def treatment(category, content):
    text = norm(content)
    if category == "SUPPORT_MESSAGE":
        # Shared support conversation is retained but identifiers must be redacted.
        return "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"
    if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        return "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"
    if category in ("EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"):
        return "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"
    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE"):
        return None, "PRESENT", "VERIFY_RECORD_PRESENT"
    return "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"

def step(phase, system, resource, operation, state, evidence=""):
    return {
        "phase": phase,
        "system_id": system or "unknown_system",
        "resource_id": resource or "unknown_resource",
        "operation": operation,
        "state": state,
        "evidence_id": evidence or "",
    }

def has_deletion_request(row):
    text = norm(row.get("request_text"))
    return any(word in text for word in DELETE_WORDS)

def process_case(row, identities, audits, activities, manifest, email_to_ids, email_to_terms):
    email = norm(row.get("email"))
    if not has_deletion_request(row):
        return "NOT_APPLICABLE", []

    ids = set(email_to_ids.get(email, set()))
    terms = set(email_to_terms.get(email, set()))
    if email:
        terms.add(email)
    # Include audit user IDs whose old/new values match the email.
    for audit in audits:
        oldv, newv = norm(audit.get("old_value")), norm(audit.get("new_value"))
        if email and (oldv == email or newv == email):
            if norm(audit.get("user_id")):
                ids.add(norm(audit.get("user_id")))
    user_ids = sorted(ids)

    hits = evidence_for_subject(manifest, email, user_ids)
    all_resources = set()
    findings, remediations, verifications = [], [], []
    active_flows = []
    restore_risks = []

    # Classify every matched evidence file. A matching line is a lead, not a definitive
    # proof of a live record, so mark it as a finding and plan treatment.
    for hit in hits:
        cat, system, evid = hit["category"], hit["system"], hit["evidence_id"]
        for resource in hit["resources"]:
            if not resource:
                continue
            all_resources.add(resource)
            treatment_op, target_state, verify_op = treatment(cat, hit["content"])
            if cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE"):
                # Retention records are not deleted; only a restore-risk record requires blocking.
                if cat == "BACKUP_ARCHIVE":
                    findings.append(step("FINDING", system, resource, "REPORT_RESTORE_RISK", "ACTIVE", evid))
                    remediations.append(step("REMEDIATION", system, resource, "BLOCK_RESTORE", "BLOCKED", ""))
                    verifications.append(step("VERIFICATION", system, resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
                else:
                    verifications.append(step("VERIFICATION", system, resource, "VERIFY_RECORD_PRESENT", "PRESENT", evid))
                continue
            # Avoid treating any textual mention as a proven remaining record, but produce a
            # conservative remediation plan for evidence that explicitly mentions the subject.
            findings.append(step("FINDING", system, resource, "REPORT_REMAINING_RECORD", "PRESENT", evid))
            if treatment_op:
                remediations.append(step("REMEDIATION", system, resource, treatment_op, target_state, ""))
                verifications.append(step("VERIFICATION", system, resource, verify_op, target_state, ""))

    # Activity logs may show active replication/indexing/import flows. Match direct subject IDs
    # or any resource found in the evidence. Avoid fabricating evidence IDs for activity rows.
    relevant_activity = activity_for_resources(activities, all_resources, user_ids)
    for act in relevant_activity:
        etype = norm(act.get("event_type"))
        result = norm(act.get("reported_result"))
        source = act.get("source_system") or "unknown_system"
        target = act.get("target_system") or source
        resource = act.get("resource_id") or "unknown_resource"
        details = norm(act.get("details"))
        active = any(x in etype + " " + details for x in ("sync", "restore", "replicat", "import", "index", "export"))
        if active and result in ("success", "active", "running", "enabled"):
            # Do not duplicate flow findings for same target/resource.
            if not any(s["operation"] == "REPORT_ACTIVE_DATA_FLOW" and s["resource_id"] == resource for s in findings):
                findings.append(step("FINDING", source, resource, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", act.get("activity_id", "")))
                remediations.append(step("REMEDIATION", target, resource, "DISABLE_DATA_FLOW", "DISABLED", ""))
                verifications.append(step("VERIFICATION", target, resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))

    # Always include the account deletion check if a stable account resource can be inferred.
    account_resources = [r for r in all_resources if "account" in norm(r) or "profile" in norm(r)]
    if not account_resources:
        account_resources = ["account_" + (user_ids[0].replace("user_", "") if user_ids and user_ids[0].startswith("user_") else email.split("@")[0].replace(".", "_"))]
    for resource in account_resources:
        if not any(s["resource_id"] == resource and s["operation"] == "VERIFY_RECORD_ABSENT" for s in verifications):
            verifications.append(step("VERIFICATION", "account_service", resource, "VERIFY_RECORD_ABSENT", "ABSENT", ""))

    # Deduplicate and sort. An incomplete case must have findings + planned remediation + checks.
    def dedup(items):
        seen, result = set(), []
        for item in items:
            key = (item["phase"], item["system_id"], item["resource_id"], item["operation"], item["state"], item["evidence_id"])
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    findings = dedup(findings)
    remediations = dedup(remediations)
    verifications = dedup(verifications)

    # If no relevant evidence is found, do not falsely certify completion: mark incomplete and
    # include a conservative account check with future remediation left for review.
    if not findings and not remediations:
        resource = account_resources[0]
        findings = [step("FINDING", "account_service", resource, "REPORT_REMAINING_RECORD", "PRESENT", "")]
        remediations = [step("REMEDIATION", "account_service", resource, "DELETE_RECORD", "ABSENT", "")]
        verifications = [step("VERIFICATION", "account_service", resource, "VERIFY_RECORD_ABSENT", "ABSENT", "")]

    # Complete can only be claimed when evidence supports verification and no finding/active
    # flow requires action. This conservative implementation rarely certifies cases.
    if not findings and not remediations and verifications and all(v["evidence_id"] for v in verifications):
        status = "COMPLETE"
        steps = verifications
    else:
        status = "INCOMPLETE"
        steps = findings + remediations + verifications

    steps.sort(key=lambda s: (
        PHASE_ORDER.get(s["phase"], 9),
        OP_ORDER.get(s["operation"], 99),
        norm(s["system_id"]),
        norm(s["resource_id"]),
    ))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    # Ensure exact key set and stable output structure.
    steps = [{
        "step_no": s["step_no"],
        "phase": s["phase"],
        "system_id": s["system_id"],
        "resource_id": s["resource_id"],
        "operation": s["operation"],
        "state": s["state"],
        "evidence_id": s["evidence_id"],
    } for s in steps]
    return status, steps

def main():
    requests = read_csv("deletion_requests.csv")
    identities = read_csv("user_identities.csv")
    audits = read_csv("user_audit_log.csv")
    activities = read_csv("system_activity.csv")
    manifest = load_evidence_manifest()
    email_to_ids, email_to_terms = build_identity_map(identities, audits, None)

    results = []
    for row in requests:
        status, steps = process_case(row, identities, audits, activities, manifest, email_to_ids, email_to_terms)
        results.append({
            "case_id": row.get("case_id", ""),
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
        })
    results.sort(key=lambda r: r["case_id"])

    with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Created {OUTPUT}")
    print(f"Processed {len(results)} requests.")
    if len(results) != 518:
        print(f"WARNING: expected 518 data rows, found {len(results)}.")
    print("NOTE: This is a best-effort heuristic solution, not a verified ground-truth audit.")

if __name__ == "__main__":
    main()
