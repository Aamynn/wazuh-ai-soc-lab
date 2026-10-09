# SSH authentication sequence investigation

Runbook ID: ssh-investigation-v1

Five or more failed logins followed by success for one host, account, and source IP in five minutes warrant review. This rule is a lab heuristic, not proof of brute force or compromise.

1. Confirm the collection window, timestamps, and source mapping.
2. Ask the account owner whether the successful login was expected.
3. Review session activity after success, privilege changes, and sensitive file access where telemetry exists.
4. Check for scheduled jobs, password changes, shared NAT, or legitimate administrative retries.
5. Record evidence and uncertainty. Escalate according to the operator's incident procedure if further evidence supports compromise.

Do not block an IP or disable an account based only on this sequence or an AI explanation. This lab has no response executor.
