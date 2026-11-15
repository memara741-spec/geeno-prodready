# File uploads (UP)

What this covers: the 6 UP checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### UP-001 — Uploads accepted without type and size limits
**Severity:** high · **Mode:** scan+review · **Applies to:** any with uploads
**Auto-fix:** assisted

**In plain words:** Uploads of any size and type are accepted.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Storage cost abuse, malware hosting and executable content on your domain.

**Fix:** Enforce size and type on the server or in storage policy and verify magic bytes.

**Verify:** Tests with an oversized file and a disallowed type.

### UP-002 — Uploaded files served from the application's origin as active content
**Severity:** high · **Mode:** review · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** Uploaded files are served from your own domain as live content, so an uploaded HTML or SVG file can run scripts.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Stored cross-site scripting.

**Fix:** Serve from a separate storage domain, force download for non-images, sanitise or rasterise SVG.

**Verify:** An uploaded HTML file does not render on your origin.

### UP-003 — Storage path or filename controlled by the user
**Severity:** high · **Mode:** scan · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** Files are stored under the name the uploader chose, so uploads can overwrite each other or escape the folder.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Overwriting other users' files and path traversal.

**Fix:** Generate random keys on the server under a per-user prefix.

**Verify:** Writing under another user's prefix fails.

### UP-004 — Private files exposed through permanent public URLs
**Severity:** high · **Mode:** scan+review · **Applies to:** supabase storage, firebase storage, s3, r2
**Auto-fix:** assisted

**In plain words:** Private files are shared through permanent public links.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Anyone with or guessing the link has the file forever.

**Fix:** Keep objects private and issue short-lived signed URLs after an authorisation check.

**Verify:** An anonymous fetch of the stored URL fails.

### UP-005 — No per-user quota on uploads or storage
**Severity:** medium · **Mode:** review · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** One account can run up your storage and bandwidth bill.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No per-user quota.

**Fix:** Track usage and enforce quotas when issuing upload URLs.

**Verify:** Exceeding the quota is refused.

### UP-006 — Image or document processing of untrusted files without limits
**Severity:** medium · **Mode:** review · **Applies to:** sharp, imagemagick, pdf libraries, ffmpeg
**Auto-fix:** assisted

**In plain words:** A crafted image or document can take the server down.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Decompression bombs and parser vulnerabilities.

**Fix:** Limit dimensions and duration, set timeouts, isolate workers, keep libraries updated.

**Verify:** Config review.


