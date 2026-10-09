# SOC investigation report

Events: **6** · Investigations: **1**

Input SHA-256: `a602988c5188dfc600b51cceb8beff8a024f61a027ef2f5d4a39eeface966ada`

## ssh\-success\-001

**Host:** lab\-linux · **Account:** demo\-user · **Source:** 192\.0\.2\.10

**Assessment:** needs\_review · **Human review required**

5 failed SSH logins preceded a successful login for the same host, account, and source IP within 300 seconds\. This sequence does not establish compromise\.

**Analysis provider:** baseline · **Fallback:** false

### Evidence timeline

| Time (UTC) | Event | Evidence ID |
| --- | --- | --- |
| 2026\-01\-01T10:00:00\+00:00 | ssh\_failed | failure\-001 |
| 2026\-01\-01T10:00:20\+00:00 | ssh\_failed | failure\-002 |
| 2026\-01\-01T10:00:40\+00:00 | ssh\_failed | failure\-003 |
| 2026\-01\-01T10:01:00\+00:00 | ssh\_failed | failure\-004 |
| 2026\-01\-01T10:01:20\+00:00 | ssh\_failed | failure\-005 |
| 2026\-01\-01T10:01:40\+00:00 | ssh\_success | success\-001 |

**Cited evidence:** failure\-001, failure\-002, failure\-003, failure\-004, failure\-005, success\-001

**Runbook:** ssh\-investigation\-v1

### Missing context

- Whether the successful login was expected
- Activity after the successful login

### Recommended checks

- Confirm the login with the account owner
- Review post\-login session activity and related authentication events

AI suggestions are not verified findings. Consult the JSON report for full provenance.
