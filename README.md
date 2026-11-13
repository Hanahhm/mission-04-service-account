 # Mission 4 — DFIR report: a service account goes rogue

**Analyst:** Hanah Marroun
**Date:** 2026-11-04 · **Part 2 added:** 2026-11-12
**Host:** `WKS-L62.hamilton.corp` (`10.50.0.62`), seat 62
**Domain:** `hamilton.corp` · **SIEM:** Microsoft Sentinel, workspace `log-sentinel-lab`
**Incident window:** from 2026-11-02 13:43 UTC (first anomalous logon), activity ongoing at time of writing

> This report has two halves. **Part 1** reconstructs the intrusion as the defender (from my Sentinel). **Part 2** reproduces the initial credential theft myself, as the attacker, from my own laptop against my own seat's account — then returns to the defender's seat to see what that attack left behind.

---

# PART 1 — Investigation (defensive)

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

# PART 2 — Reproducing the attack (offensive)

> From my own laptop (Kali over Tailscale, my attack machine), starting from nothing but my own domain account, I reproduced the credential theft the intruder used — against **my own seat's** service account (`svc-app62`) only, signed on to **my own** workstation only. No other seat was touched. Then I switched back to defender to see what my own attack left in Sentinel.

## 6. Attack narrative — Kerberoasting, step by step

- **Step 5 — Find the roastable account.** Signed in as an ordinary domain user with no special rights, I asked the domain controller which accounts carry a Service Principal Name. `svc-app62` carries **`MSSQLSvc/app62.hamilton.corp`** — it advertises that it runs a **SQL Server (MSSQL)**. That service type is exactly what the Recon challenge asked for. Any signed-in user can ask this; it is the directory doing its normal job.

- **Step 6 — Request the ticket and carry it away.** I requested a Kerberos service ticket (TGS) for `svc-app62` and saved it in a crackable form. Notice what I did **not** need: no password for `svc-app62`, no failed logon, no elevated right — I only asked for a service, the way any user does all day. The saved ticket began with **`$krb5tgs$23$`**: the `23` means it is encrypted with **RC4**, the old, weak algorithm the account still allows.

- **Step 7 — Crack it offline.** On my own laptop, at my own pace, with nobody on the domain able to see it, I cracked the ticket against the `rockyou` wordlist. It fell in **~7 seconds** — proof the account's password was weak (a dictionary word plus a year). This is the whole danger of Kerberoasting: the cracking happens entirely offline, invisible to the network and to any SIEM.

- **Step 8 — Become the account.** I used the recovered password to sign on to **my own workstation** as `HAMILTON\svc-app62` over RDP, confirming the credential works and retrieving the proof that only that account can read (submitted as the Kerberoast flag).

## 7. MITRE ATT&CK mapping (the attack)

| Step | Tactic | Technique (ID + name) | What I did | Defender's view in my Sentinel |
|---|---|---|---|---|
| 5 — enumerate SPNs | Discovery / Credential Access | **T1558.003** Kerberoasting (reconnaissance phase) | Asked the DC for accounts carrying an SPN | **Invisible** — an LDAP query to the DC, off my workstation |
| 6 — request the TGS | Credential Access | **T1558.003** Kerberoasting | Requested + exported the RC4 service ticket for `svc-app62` | **Invisible** — the ticket request (Event 4769) is logged on the **DC**, which I do not collect |
| 7 — crack offline | Credential Access | **T1110.002** Brute Force: Password Cracking | Cracked the RC4 ticket with `rockyou`, offline | **Invisible** — happens entirely on my laptop |
| 8 — use the account | Lateral Movement | **T1078.002** Valid Accounts: Domain Accounts; **T1021.001** Remote Services: RDP | RDP'd into `WKS-L62` as `svc-app62` | **Visible** — SecurityEvent 4624, LogonType 10, from 10.50.0.1 |

## 8. What a defender could see — and could not

- **My sign-on IS visible.** My RDP logon as `svc-app62` landed in Sentinel as **SecurityEvent 4624, LogonType 10 (RemoteInteractive)**, from **`10.50.0.1`**, LogonProcessName **`User32`**, on **2026-11-04 ~15:14 UTC**.

- **Telling my logon apart from the intruder's.** The two `svc-app62` logons share the same account name but differ clearly:

  | | Intruder (Part 1) | Me (Part 2) |
  |---|---|---|
  | **LogonType** | 4 (Batch) — a scheduled task | 10 (RemoteInteractive) — RDP |
  | **Source** | no IP; local process (`Advapi`) | `10.50.0.1`, over the network (`User32`) |
  | **Pattern** | recurs every 15 min, 02–04 Nov | one-off, 04 Nov, outside the incident window |

  A defender separates the two by **LogonType**, **source** and **timing/pattern** — never by the account name, which is identical.

- **The theft itself is invisible.** The steps that actually stole the credential — enumerating the SPN, requesting the ticket, cracking it — **appear nowhere in my Sentinel**. The ticket request is an **Event 4769** logged **on the domain controller**, not on my workstation, and I only collect my workstation's logs; the cracking happened offline on my laptop. This is the core lesson: Kerberoasting leaves almost no trace on the victim host — the only on-host event is the eventual logon, which looks like an ordinary RDP sign-on.

## 9. Remediation — now that I have run the attack myself

- **Kill the root cause — the weak, RC4 service-account password.** Replace `svc-app62` with a **group Managed Service Account (gMSA)** (auto-rotated 120-char password) or at minimum a long random password (25+ chars), and **disable RC4 / enforce AES** on the account. A strong key makes the offline crack infeasible even when the ticket is stolen.
- **Deny the service account interactive and RDP logon** on workstations (a tiering model), so even a cracked credential cannot be used to sign on.
- **See the theft at the source.** Collect **Event 4769** from the **domain controller** into Sentinel and alert on service-ticket requests that use **RC4 (encryption type `0x17`)**, or that request many SPNs at once — that is the signature of Kerberoasting at the moment it happens.
- **Least privilege** on `svc-app62`, so that even a successful compromise grants as little as possible.

### Stretch — the detection question I wish my SIEM answered on its own
*"Alert me whenever a service account's Kerberos ticket is requested with RC4 encryption, or whenever a service account signs on interactively (LogonType 10) to a workstation."* Both are cheap to express once the DC's 4769 events and the workstations' 4624 events are collected — and either one would have lit up this entire chain. The single change that would have broken it outright: a **gMSA with AES-only** on `svc-app62`, which removes the weak, crackable key the whole attack depends on.

---

## Appendix — CTFd progress (status only, not the hand-in)

| Challenge | Status |
|-----------|--------|
| Mission 4 — Recon (service type from the SPN) | submitted |
| Mission 4 — Data staged (proof file in the staging folder) | submitted |
| Mission 4 — Persistence (proof in the scheduled task) | submitted |
| Mission 4 — Kerberoast (Part 2, reproduced the theft) | submitted |

*(Flag values and credentials are deliberately not reproduced in this report — the report, not the flag, is the deliverable.)*


## Detection — catching Kerberoasting at the source (Mission 5)

**Context.** In Part 2 I showed that the Kerberoasting ticket request never reached my workstation's Sentinel — it is an event written on the **domain controller**. With the DC now feeding a shared Sentinel workspace (`log-hamilton`), I hunted the request at the source, turned it into a scheduled detection rule, and proved it fires.

**The rule query:**
```kql
SecurityEvent
| where EventID == 4769
| extend P = parse_xml(EventData).EventData.Data
| mv-apply P on (summarize Bag = make_bag(bag_pack(tostring(P['@Name']), tostring(P['#text']))))
| extend Requestor   = tostring(Bag.TargetUserName),
         ServiceName = tostring(Bag.ServiceName),
         Encryption  = tostring(Bag.TicketEncryptionType),
         Ip          = tostring(Bag.IpAddress)
| where Encryption == "0x17"          // RC4 — the weak algorithm Kerberoasting requests
| where ServiceName !endswith "$"     // exclude machine accounts
| where ServiceName != "krbtgt"       // exclude the ticket-granting service
| project TimeGenerated, Requestor, ServiceName, Encryption, Ip
```

**What it detects, and why that detail gives it away.** Event **4769** is written by the domain controller every time a Kerberos service ticket (TGS) is requested. The useful fields are not in their own columns — they are packed into the event's `EventData` field as a small XML document — so the rule uses **`parse_xml`** to pull out the requesting account, the target service account, the encryption type and the source IP by name. The giveaway is the **encryption type**: a Kerberoasting tool deliberately asks for the ticket with **RC4 (`0x17`)**, the old, weak algorithm, because it is the only one it can crack offline. Over a 30-day window the workspace held **13,741** AES (`0x12`) service tickets and only **31** RC4 (`0x17`) — RC4 is ~0.2% of all ticket traffic. A service ticket requested with RC4 for a human-style service account is therefore a strong, low-noise signal of Kerberoasting.

**MITRE ATT&CK:** **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting (tactic: Credential Access).

**False positives excluded, and why.** Two kinds of accounts request tickets constantly and are never what I am looking for: **machine accounts** (names ending in `$`) and the domain's own ticket-granting service, **`krbtgt`**. Both are excluded so the rule only surfaces RC4 requests for the user *service* accounts that Kerberoasting actually targets.

**How often it runs and how far back it looks.** I measured the ingestion delay by replaying the ticket request and watching for it in the workspace: the event became queryable **~5 minutes** after I made the request. The rule runs **every 10 minutes** and looks back over the **last 1 hour**. The look-back (60 min) is deliberately longer than the run interval (10 min) plus the ingestion delay (~5 min): if the look-back equalled the run interval, an event that ingests late could arrive after one run's window closed and before the next one opened, and never be seen. A 1-hour look-back guarantees every event is re-scanned by the following run, and the incident grouping (match-all-entities, 5-hour window) collapses the resulting repeats into a single incident.

**Tuning after the first live detection.** Seeing the rule fire on the real attack exposed two things to improve. First, the same event surfaced as several alerts: with a 1-hour look-back and a 10-minute run interval, each event is re-scanned by roughly six consecutive runs. The fix is to narrow the look-back to ~20 minutes — just above the measured ingestion delay — so each event is reported about once while still never being missed. Second, the attack's alerts joined my earlier replay's incident (3091) instead of opening their own, because my alert grouping matches on account + IP over a 5-hour window and the attacker reused the same `training01` account from the same gateway; shortening that grouping window to ~1 hour makes a fresh attack open a fresh incident.

**Proof it fired.** I replayed the ticket request at **13:29 UTC**. My rule `L62 - Kerberoasting - RC4 service ticket` raised incident **3091** at **13:35** (~6 minutes later), Medium severity. Thanks to the entity mapping, the incident shows the requesting account (`training01@HAMILTON.CORP`) and the source IP (`10.50.0.1`) directly, so a triage analyst sees who and from where without rerunning the query.

![Incident 3091 raised by rule L62 — requester training01 and source IP 10.50.0.1 (Defender portal, Spanish UI)](step7_proof_L62.png)

**Triage — the attack I did not launch.** On **2026-11-13 at 14:20:00–14:20:01 UTC** my rule fired on activity I did not cause. The account `training01` requested RC4 service tickets for **two different service accounts — `svc-app50` and `svc-app62` — within the same second**, from the lab gateway `10.50.0.1`.

- **Who / what / where / when / how many:** requester `training01`; targets `svc-app50` and `svc-app62` (2 distinct service accounts); source `10.50.0.1`; at `14:20:00.803` and `14:20:01.014` UTC; two requests in ~0.2 seconds.
- **Classmate replay, or an attack?** A legitimate replay is one account requesting its **own single seat** — and the earlier `training01` activity was exactly that, one seat at a time spread across several days. This is the opposite: **one account requesting tickets for multiple distinct service accounts in under a second**, the signature of an automated **mass-roast**. So this is an **attacker** (using the `training01` credential leaked in Mission 3), not a classmate's normal replay. It hit seats indiscriminately, including my own (`svc-app62`) and a classmate's (`svc-app50`).
- **A triage trap worth noting:** because the attacker reused the same account and source IP as earlier benign use, Defender grouped the new alerts into my existing incident (3091) by matching entities. A defender who reads only the incident header could mistake it for more of the same replay — the giveaway is in the individual alerts (their sub-second timestamps and the several target service accounts). My rule, enabled before the attack, caught it live.

**What a defender in this domain still cannot see.** Every ticket request — mine and every classmate's — arrives from the same address, `::ffff:10.50.0.1`, the lab gateway that NATs all traffic. The source IP therefore shows *that* an attack happened and *which domain account* asked, but not *which physical machine* it came from: the host behind the gateway stays invisible.
