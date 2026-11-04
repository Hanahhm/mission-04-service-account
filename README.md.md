# Mission 4 — DFIR report: a service account goes rogue

**Analyst:** Hanah Marroun
**Date:** 2026-11-04
**Host:** `WKS-L62.hamilton.corp` (`10.50.0.62`), seat 62
**Domain:** `hamilton.corp` · **SIEM:** Microsoft Sentinel, workspace `log-sentinel-lab`
**Incident window:** from 2026-11-02 13:43 UTC (first anomalous logon), activity ongoing at time of writing

---

## 1. Executive summary — for a manager

A service account (`svc-app62`) that normally only runs a background application was taken over and used by an attacker on my workstation. Once in, it inspected the machine, collected a set of **customer records** (names, emails, subscription plan and monthly revenue) and left them bundled on disk ready to steal. It also planted a hidden **scheduled task** that re-runs every 15 minutes, which means the intruder still has an automated foothold on the machine right now. The account was most likely stolen through **Kerberoasting** — a technique that cracks a service account's password offline, with no failed logins and no alarm, when the password is weak. The incident is **not yet contained**: the account is compromised and the scheduled task is still active until it is removed.

---

## 2. Technical narrative — for a technician

- **Stage 0 — how the account was stolen (root cause, not in my Sentinel).** The account `svc-app62` is a domain service account that carries a Service Principal Name (SPN), so it advertises the kind of service it runs. In Active Directory, any ordinary domain user can request a Kerberos service ticket for such an account; that ticket is encrypted with the account's own password and can be carried away and cracked offline (**Kerberoasting**). This step happened at the domain controller, so it does not appear in my workstation's Sentinel — it is reasoned from the account type and from what followed. It works when the password is weak and when the account still allows legacy RC4 encryption.

- **Stage 1 — the logon that should not exist.** On **2026-11-02 at 13:43 UTC**, `HAMILTON\svc-app62` signed on to `WKS-L62` with **LogonType 4 (Batch)** — the logon type used by scheduled tasks. A service account signing on to a workstation is behaviour that should never happen, and it recurs 179 times through 2026-11-04 (the planted task firing on its schedule). *Evidence: SecurityEvent, EventID 4624.*

- **Stage 2 — what the account did.** Immediately after the first logon, the account ran a burst of reconnaissance through PowerShell: `whoami` and `whoami /all` (who am I, what privileges), `net user svc-app62` and `net localgroup administrators` (group membership / am I admin), and `ipconfig /all` (network position). This is classic host and account discovery. *Evidence: SecurityEvent, EventID 4688, with full command line (process-creation auditing enabled since Mission 2).*

- **Stage 3 — the data it gathered and staged.** The attacker's PowerShell payload (`C:\ProgramData\m4_session_payload.ps1`) created a staging folder `C:\Users\Public\Desktop\staging\` and wrote **`customers.csv`** into it — customer records with `customer_id`, `full_name`, `email`, `plan` and `mrr` (monthly recurring revenue). The data was written with the PowerShell `Set-Content` cmdlet, which runs inside PowerShell and spawns no child process, so it does **not** appear as a process-creation event — the trace is the file left on disk. *Evidence: the staged file and the payload script on the host; the surrounding recon in SecurityEvent 4688.*

- **Stage 4 — the way it left itself back in.** A scheduled task named **`\M4-SvcApp62-Persistence`**, running as `svc-app62`, executes every **15 minutes** and runs a short `cmd.exe` command that appends a marker to `C:\ProgramData\m4-persistence-log.txt`. A task that runs on its own, on a schedule, with nobody logged in, is what turns this from an incident that *happened* into one that is *ongoing*. *Evidence: `schtasks /query /fo LIST /v` on the host. Note: the scheduled-task-creation event (4698) is **not collected** in my Sentinel, so this step is invisible to the SIEM — a monitoring gap, see §5.*

---

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I observed | Where I can prove it |
|---|---|---|---|---|
| 0 — root cause | Credential Access | **T1558.003** Steal or Forge Kerberos Tickets: Kerberoasting | SPN-bearing service account whose password was cracked offline | Reasoned — happened off my workstation (domain controller) |
| 1 — initial access | Initial Access / — | **T1078.002** Valid Accounts: Domain Accounts | `svc-app62` logon (Batch) on a workstation, 2026-11-02 13:43 UTC | SecurityEvent, EventID 4624 |
| 2 — execution | Execution + Discovery | **T1059.001** PowerShell; **T1033** System Owner/User Discovery; **T1087** Account Discovery; **T1069.001** Local Groups; **T1016** System Network Config Discovery | whoami, net user / net localgroup, ipconfig run after logon | SecurityEvent, EventID 4688 (command line) |
| 3 — collection / staging | Collection | **T1005** Data from Local System; **T1074.001** Local Data Staging | `customers.csv` written to `...\staging\` by the payload | File + payload on host; recon in SecurityEvent 4688 |
| 4 — persistence | Persistence | **T1053.005** Scheduled Task | `M4-SvcApp62-Persistence` runs every 15 min as `svc-app62` | `schtasks /query` on host (4698 not collected in Sentinel) |

---

## 4. Impact and containment

- **What was taken.** A small set of **customer records** — `customer_id`, `full_name`, `email`, subscription `plan`, and `mrr` (monthly recurring revenue) — for 3 customers, staged in `customers.csv`. This is personal data (names, emails) combined with commercial/financial data (revenue per customer). The data set is simulated lab data (`example.com` addresses, marked `EXFIL-TEST-MARKER-M4`) but is treated here as a real breach. It was **staged** and ready to leave; there is no evidence in my workstation's logs that it was actually exfiltrated off the network.

- **Still inside?** **Yes — this incident is ongoing.** The scheduled task `M4-SvcApp62-Persistence` runs every 15 minutes as `svc-app62` and will keep running until it is removed. The service-account credential itself is compromised (recovered via Kerberoasting) and is valid across the domain, so the attacker can return even without the task.

- **Containment now (today).** 1) Disable and delete the scheduled task `M4-SvcApp62-Persistence`. 2) Disable `svc-app62` and force a password reset (ideally migrate it to a managed service account). 3) Delete the staged folder `C:\Users\Public\Desktop\staging\` and the payload `m4_session_payload.ps1`. 4) Hunt for the same task name and the same account logon on every other machine in the domain, since the cracked credential works domain-wide.

---

## 5. Remediation — stop it happening again

| Weakness | Why it worked | Missing control + fix |
|---|---|---|
| Service account with an SPN and a weak, RC4-crackable password | Any domain user could request its ticket and crack the password offline (Kerberoasting), with no alarm | Use a long random password (25+ chars) or a **group Managed Service Account (gMSA)**; disable RC4 / enforce AES; apply least privilege to the account |
| Service account allowed to log on to a workstation | Nothing stopped a non-human account from signing on interactively/batch | Deny service accounts the "log on as a batch job / locally" right on workstations; apply a tiering model |
| Scheduled-task creation not audited (EventID 4698 absent in Sentinel) | The persistence mechanism was invisible to the SIEM | Enable **Audit Other Object Access Events** and collect 4698; alert on new scheduled tasks, especially run by service accounts |
| PowerShell actions (the staging) left no process event | `Set-Content` runs inside PowerShell, so the data collection was invisible in 4688 | Enable **PowerShell Script Block Logging (4104)** and module logging, and collect them into Sentinel |
| Customer data readable and staged on disk with no egress control | The data could be gathered and parked ready to exfiltrate | Data Leakage Prevention / egress filtering; restrict who can read customer data at rest |

---

## Appendix — CTFd flags (engine, not the hand-in)

| Challenge | Status |
|-----------|--------|
| Mission 4 — Recon (service type from the SPN) | submitted |
| Mission 4 — Data staged (proof file in the staging folder) | submitted |
| Mission 4 — Persistence (proof in the scheduled task) | submitted |

*(Flag values and credentials are deliberately not reproduced in this report.)*
