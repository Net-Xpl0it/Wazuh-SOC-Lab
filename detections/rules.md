# Custom detection rules

Four custom rules, each fired on live events. Rule file: [`local_rules.xml`](local_rules.xml).

| Rule ID | Trigger | Level | MITRE ATT&CK | Fires when |
|---|---|---|---|---|
| 100202 | Windows Event ID 4724 | 10 | T1098 Account Manipulation | An administrator resets a user's password |
| 100203 | Windows Event ID 4726 | 12 | T1531 Account Access Removal | A user account is deleted |
| 100204 | Windows Event ID 4720 | 12 | T1136 Create Account | An account named `the_user` is created |
| 100101 | 3+ SSH auth failures, same source IP, 120s window | 10 | T1110 Brute Force | Repeated SSH login failures match the same source IP |

Windows rules carry a `MYDFIR-Jayasurya` prefix so lab alerts are easy to tell apart from stock Wazuh alerts. Rule 100101 reuses the stock description text since it extends a stock rule's frequency logic rather than relabeling a single event.

## 100202: Password reset by an administrator

- **Detects:** Event ID 4724, a password reset performed by another account.
- **Parent:** Wazuh rule 60103 (Windows audit success event, level 0), so it only fires on successful operations.
- **Why level 10:** A reset can be a normal helpdesk action, but it is also how an attacker takes over an account, so it deserves analyst attention.
- **Observed:** Two alerts, at 15:28:28 and 15:37:25 on Aug 19, 2026.

## 100203: Account deleted

- **Detects:** Event ID 4726, a user account deletion.
- **Parent:** Wazuh rule 60111 ("User account disabled or deleted", level 8), which matches event IDs 629, 630, 4725 and 4726.
- **What I changed:** The stock rule already alerts on deletion at level 8. This rule narrows to 4726 only, raises the severity to 12 and replaces the generic text with environment-specific wording.
- **Observed:** Fired on Aug 19, 2026 (15:37:37) and again on Oct 10, 2026 (12:21 IST).

## 100204: Watchlisted account created

- **Detects:** Event ID 4720 where the new account is named `the_user`.
- **Parent:** The `windows_security` rule group.
- **Limitation:** The username is hard-coded for the lab exercise. A production version would alert on every 4720 event and use a list of suspicious names to set the severity. In the Oct 10, 2026 re-test, the account created did not match `the_user`, so the event was handled by a stock Windows rule ("User account enabled or created") instead of 100204 — expected behavior given the hard-coded field match, not a rule failure.

## 100101: SSH brute force (same source IP)

- **Detects:** Three or more SSH authentication failures from the same source IP within a 120-second window.
- **Parent:** Extends stock rule 5760 (sshd authentication failed, level 5) using `if_matched_sid` with `frequency="3"`, `timeframe="120"` and `<same_source_ip />`.
- **Why it's separate from stock rule 5763:** Wazuh ships rule 5763 with the same idea at `frequency="8"`, `timeframe="120"`, `ignore="60"`. This rule lowers the threshold to 3 failures so it fires sooner in a small lab environment, at the cost of being noisier in a real one.
- **Test method:** From a second machine, SSH password authentication was temporarily re-enabled on the Ubuntu endpoint (`/etc/ssh/sshd_config.d/50-test.conf`, `PasswordAuthentication yes`) and a loop of failed logins (`sshpass`) was run against it over two terminals — one holding a legitimate session, one running the failed attempts — to confirm the brute-force detection does not depend on the attacker and the defender using the same session.
- **Observed:** Fired on Oct 10, 2026 at 11:56 IST, `rule.firedtimes: 1`, matching 3 failed logins for user `ubuntu` within the timeframe. Confirmed in Discover and in the "Linux Failed-SSH Authentication Activity" dashboard panel (counts of 1-2-2 across three near-simultaneous timestamps).
- **Cleanup:** `PasswordAuthentication` was reverted to the AWS default (key-only) immediately after the test.

## Notes on scope

Only detections with captured evidence are published here. Windows account auditing must be enabled on the endpoint for the 472x event IDs to reach Wazuh. Rules configured but not exercised with evidence (Guest-account enable/4722, self-service password change/4723, active-response firewall block) are described in the main README under "Limitations" rather than claimed here.
