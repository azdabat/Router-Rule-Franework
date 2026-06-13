# Router Rule: LOLBin Multi-Technique Evasion Surface

**File:** `RR_LOLBin_MultiTechnique_Surface.kql`  
**Architecture:** Router Rule — Triage Surface  
**Author:** Ala Dabat | MTDF 2026  
**MITRE:** T1003.001 · T1562.001 · T1562.002 · T1027 · T1105 · T1218  

---

> *"This rule casts the net. The composites pull it in."*

---

## Why This Is a Router Rule

Five techniques. Four noise domains. One adversary goal: **bypass defences and establish execution**.

The techniques covered — LSASS dumping, AMSI bypass, Defender tampering, encoded payloads, and proxy downloads — all serve the same adversary objective but each requires completely different suppression logic in production. Combining them into a composite would produce a rule that cannot be tuned for one technique without creating blind spots in another.

| Technique | Noise Domain | Why It Cannot Share Suppression |
|-----------|-------------|--------------------------------|
| LSASS Dump | AV/EDR process noise around LSASS | Suppressing AV context blinds you to non-AV attackers |
| AMSI Bypass | Every PowerShell session touches AMSI strings | Suppressing PS scripting blinds you to bypass attempts |
| Defender Tamper | MDM/Intune legitimately uses Set-MpPreference | Suppressing MDM context hides attacker tampering |
| Encoded Payload | Encoded commands used in legitimate PS admin scripts | Suppressing encoded admin blinds you to encoded malware |
| Proxy Download | certutil/bitsadmin already in Ingress Transfer Router | Routed to Router Rule 1 — different noise domain entirely |

This rule fires broadly, scores low (threshold 30), and tells the analyst **which composite to run next**. It does not confirm truth — it surfaces intent.

---

## Red Team Perspective

### LSASS Dump via comsvcs.dll

The most common post-exploitation credential harvest in enterprise environments. After gaining elevated execution, the attacker uses rundll32 to invoke the `MiniDump` export of `comsvcs.dll` — a legitimate Windows DLL that happens to expose a full memory dump function.

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\lsass.dmp full
```

The ordinal form is used to evade string-based detection:
```cmd
rundll32.exe comsvcs.dll #24 <lsass_pid> C:\Temp\out.dmp full
```

**Why it works:** comsvcs.dll is a signed Microsoft DLL. rundll32 is a signed Microsoft binary. The network connection is zero. No new process is created. Many EDRs miss this entirely because there is no suspicious binary, no suspicious parent, and no network activity — just a legitimate OS binary being told to dump a process.

**Common frameworks:** Cobalt Strike `hashdump`, Metasploit `post/windows/gather/credentials/credential_collector`, manual Empire post-exploitation.

### AMSI Bypass

AMSI (Antimalware Scan Interface) is the Windows API that allows security products to inspect script content before execution. An attacker who bypasses AMSI can run any PowerShell payload without it being scanned.

Classic bypass — patches the `amsiInitFailed` field in memory:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Newer variants use `AmsiScanBuffer` patching directly — bypassing the API at a lower level and defeating products that monitor `amsiInitFailed`.

**Why it works:** This is entirely in-memory. No file is written. No child process is spawned. The bypass happens inside the current PowerShell session. Most products detect this via AMSI itself — which the bypass has just disabled. Once bypassed, the attacker has an open execution channel.

### Defender Tamper

Using `Set-MpPreference` to add exclusion paths or disable real-time monitoring:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```

**Why it works:** `Set-MpPreference` is a legitimate cmdlet used by MDM solutions including Intune. The operation itself looks identical to legitimate management. The attacker is not installing anything, creating any file, or making any network connection. They are simply changing a configuration value through an approved API.

### Encoded Payload Execution

PowerShell's `-EncodedCommand` flag accepts base64-encoded commands to bypass command-line logging and string-based detections:
```cmd
powershell.exe -NoP -NonI -W Hidden -Enc [base64_of_payload]
```

A 400+ character encoded command is almost never legitimate administration. It is almost always obfuscation.

---

## Blue Team Perspective

### What This Rule Detects

The router rule detects the **presence of known-bad primitives** across five technique surfaces in a single broad pass. It is not trying to confirm the attack — it is trying to ensure nothing slips past entirely while dedicated composites are being built.

### What It Does Not Detect

- Fileless variants where no command-line indicator is present (these require substrate-first composites)
- AMSI bypasses that do not contain the known string patterns (novel bypasses)
- LSASS dumps via direct syscall (no rundll32 involved)
- Defender tamper via registry modification (covered by Registry Persistence Router Rule)

### Routing Logic

When this rule fires, the analyst receives a `RoutingDirective` that names the composite to run:

- `IsLSASS == 1` → Run T1003.001 LSASS Composite on that DeviceId
- `IsAMSI == 1` → Run T1562.002 AMSI Bypass Composite on that DeviceId
- `IsDefTamper == 1` → Run T1562.001 Defender Tamper Composite on that DeviceId
- `IsEncoded == 1` → Run T1027 Encoded Payload Composite on that DeviceId
- `IsProxy == 1` → Route to Ingress Transfer Router Rule — already covered

### False Positive Profile

**Most common false positives:**

| Source | Signal | Mitigation in Rule |
|--------|--------|--------------------|
| Intune MDM | Set-MpPreference during device enrollment | `IsManagedAcct` soft down-score |
| Security tools | AMSI strings in AV/EDR process command lines | `IsManagedAcct` soft down-score |
| Admin scripts | Encoded commands in IT automation | Low risk score without additional signals |

### Analyst Workflow

```
Router fires → RiskScore >= 30
     ↓
Check RoutingDirective field
     ↓
Run named composite on DeviceId from this alert
     ↓
Composite confirms or denies minimum truth
     ↓
If confirmed: create incident, pivot on entity keys
If denied: tune router threshold or add soft penalty
```

---

*Part of the MTDF Router Rule Framework*  
*Author: Ala Dabat | [github.com/azdabat](https://github.com/azdabat)*
