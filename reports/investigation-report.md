# Wazuh SOC Investigation Report

**Lab:** MYDFIR-JAYASURYA Wazuh-SOC Lab
**Date of investigation:** August 19, 2026 (IST)
**Investigator:** Jayasurya D K

## Lab environment

Wazuh runs on a Debian laptop (manager, indexer and dashboard) and monitors a Windows Server 2022 instance and an Ubuntu 24.04 instance on AWS EC2. My home router restricts port forwarding, so the endpoints connect to the manager over Tailscale, a mesh VPN. I access the Linux instance with SSH key pairs and the Windows instance over RDP using Remmina. Running VMware alongside the manager on Debian used too much RAM, so I deployed the endpoints on EC2. That gave me hybrid cloud and on-premises detection practice without deleting or backing up any data.

## Findings

- **RDP brute force was detected in real time.** A password brute-force attack run with Hydra against the Windows Server's RDP service produced 16 failed logon events (Event ID 4625), all recorded by Wazuh. The attack did not succeed (Figure 3).
- **Account lifecycle activity was visible by Event ID.** Account creation, enabling, password reset, disabling, deletion and group membership changes were captured (Event IDs 4720, 4722, 4724, 4725, 4726, 4732, 4733 and 4738) and described by Wazuh's built-in Windows rules (Figure 3).
- **File Integrity Monitoring (FIM) was configured and validated for the first time.** A file in a monitored directory was modified twice, deleted and added back, producing rules 550, 553 and 554 in real time (Figure 1).
- **Custom detection rules improved alert clarity.** Rules 100202, 100203 and 100204 replaced generic descriptions with environment-specific alert text, MITRE ATT&CK mappings and, for account deletion, a higher severity (level 12 instead of the stock level 8) (Figure 2).
- **Failed SSH authentication was collected from the Ubuntu endpoint** and displayed on the dashboard (Figure 3).

## Investigation summary

**Who:** Jayasurya D K, sole investigator, simulated both the attacker and analyst roles. No external parties were involved. Every action in this report, from launching the attacks to detecting them, was carried out and observed by the same person.

**What:** A detection validation exercise across the hybrid lab. It covered an RDP brute-force attempt against the Windows Server using Hydra, Windows account lifecycle changes, failed SSH logins on the Ubuntu endpoint, File Integrity Monitoring on a watched directory and custom Wazuh rules mapped to MITRE ATT&CK.

**When:** August 19, 2026 (IST). Everything took place in one session: file integrity events between 13:56 and 13:59, and the custom rule alerts between 15:28 and 15:37. This was a bounded lab exercise, not an ongoing incident.

**Where:** The home hybrid lab. The Wazuh manager, indexer and dashboard run on a Debian laptop, and the targets are a Windows Server 2022 and an Ubuntu 24.04 instance on AWS EC2, connected over Tailscale.

**Why:** Not a real incident. This was a deliberate, self-directed training exercise under the MyDFIR SOC Analyst challenge (credit to MyDFIR and Steven Mah for the exercise design), aimed at checking that the detection stack catches known attack patterns rather than only reading about them.

**How:**
- RDP brute force: Hydra run against the RDP service with repeated password attempts.
- Account changes: Windows account management commands run directly, generating Event IDs 4720, 4722, 4724, 4725, 4726, 4732, 4733 and 4738.
- SSH: failed login attempts against the Ubuntu endpoint, shown in a dashboard panel.
- FIM: a file created, modified and deleted in a monitored directory to trigger real-time alerts.
- Custom rules: written in `local_rules.xml` to replace generic descriptions with environment-specific, MITRE-mapped alert text.

## Evidence

- Figure 1: FIM events on the Windows endpoint (`../screenshots/01-fim-events.png`)
- Figure 2: Custom rules 100202, 100203 and 100204 firing (`../screenshots/02-custom-rule-alerts.png`)
- Figure 3: SOC activity dashboard (`../screenshots/03-soc-dashboard.png`)
- Figure 4: Custom rule 100101 (SSH brute force) firing (`../screenshots/04-ssh-bruteforce-alert.png`)
- Figure 5: Dashboard during the Oct 10 re-test session (`../screenshots/05-dashboard-oct10.png`)
- Figure 6: Windows account activity and Linux failed-SSH panels, Oct 10 (`../screenshots/06-windows-linux-panels.png`)

## Addendum: October 10, 2026 re-test session

The first session (Aug 19) proved most detections but left the SSH brute-force rule (100101) and some account-lifecycle paths unconfirmed. A second, focused session re-triggered them:

- **SSH brute force (rule 100101).** The Ubuntu endpoint has password authentication disabled by default (AWS image default, key-only). It was temporarily re-enabled (`/etc/ssh/sshd_config.d/50-test.conf`) to allow a password-based test, then reverted immediately after. The test was run from two terminals: one held a normal SSH session to confirm the endpoint stayed reachable, the other ran a loop of failed password attempts against it. Rule 100101 fired after 3 failures within the 120-second window, confirmed in both Discover (Figure 4) and the dashboard's SSH panel (Figure 6).
- **Account lifecycle events.** Further Windows account changes (4738, 4725, 4720, 4726) were generated and captured; rule 100203 fired again on the 4726 deletion event (Figure 6).
- **RDP brute force.** A further attempt was made to generate failed RDP logons (Event ID 4625) against the Windows endpoint over Tailscale, to repopulate the dashboard's "Failed RDP Logon Attempts" panel for the current session. At the time Figure 5 was captured the panel still showed 0 for the active window; the 16 failed-logon count from Aug 19 remains the proven RDP evidence for this report (Figure 3).
- **Guest-account enable (rule 100200) and self-service password change (rule 100201)** were not exercised in this session and remain configured but unproven, as noted under Limitations.

Time of this session: approximately 11:55-12:21 IST on October 10, 2026.

## Recommendations

- **Reduce direct RDP exposure with a bastion host.** Placing a gateway (for example Azure Bastion, or an SSH/RDP gateway) between the internet and the target cuts the attack surface.
- **Move toward centralized identity instead of local accounts.** Managing accounts per machine, as done here, does not scale and is harder to audit. Centralized identity (AD on-prem or Entra ID in the cloud) combined with just-in-time privileged access keeps admin rights temporary instead of standing.
- **Apply least privilege by default.** Test accounts such as Guest and `the_user` were added straight to local Administrators for convenience. In a real environment, accounts should start with minimum access and be elevated only for a specific reason.
- **Enforce a stronger password policy, not just detection.** Windows already rejected a weak password for a test account because it failed complexity requirements, which is the system doing its job. Detection catches brute-force attempts, but a solid password policy stops many of them from being viable at all.
- **Extend FIM coverage to sensitive system paths.** Only a test directory is monitored right now. Watching paths such as `/etc` on Linux or `System32\drivers\etc` on Windows would catch real configuration or binary tampering, not just demo files.
- **Keep building custom rules instead of relying on default descriptions.** Clear, environment-specific wording cuts alert fatigue and makes investigations faster to read.
- **Add an endpoint protection layer alongside Wazuh.** Wazuh and Sysmon give visibility but do not stop malware on their own. A properly configured EPP/EDR tool such as Windows Defender fills that gap by blocking known threats instead of just logging them.
