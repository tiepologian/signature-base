# Operation Turb00 — Part 2: Indicators of Compromise

IOCs for the multi-stage **HijackLoader → Vidar v2.1 + SnappyClient RAT** campaign analyzed in
*Operation Turb00 — Part 2: A Multi-Stage HijackLoader Campaign Delivers Vidar v2.1*.


> ⚠️ Several files are **legitimate, signed applications** abused as side-loading hosts (Radmin VPN, Opera,
> dBpoweramp, Crisp, Qihoo 360, Microsoft/Qt runtimes). They are listed for completeness and **are not
> malicious on their own**.

---

## 1. File Hashes (SHA-256)

### 1.1 Delivery — 7-Zip SFX and its contents

| File | Role | SHA-256 |
|---|---|---|
| `Setup.exe` | 7-Zip SFX lure (top-level sample) | `1bb2771002bf8240e34e8284048bfc1db8dd7cdade7a7afb4a2cfbe02b1a9749` |
| `WizardDa42.exe` | Radmin VPN GUI (legit, signed) — side-load **host** | `716a11cdc1b12827ee18027caa947f813cb3550412b5dcaae427be3bbcc0221f` |
| `Qt5Core.dll` | **TROJANIZED** — sideloaded HijackLoader (signature invalid) | `c73b6080ff81a42336be2baa3a159f746a054032615f53d0e1ff56d57c357b14` |
| `shader128.map` | HijackLoader shellcode | `5ebddd8e1d04b75331aae732364cce2da698639263b18b25fa06b92e4778ddc2` |
| `scenesync45.xml` | HijackLoader container | `32b2344e7310ffad2bfd17454bb64cdabc0c35fb3b55e29627c0aeced6c4e0b7` |

### 1.2 HijackLoader bundle — 13 PEs unpacked from `scenesync45.xml`

| File / Identity | Role | SHA-256 |
|---|---|---|
| `Crisp.exe` (Crisp IM) | Signed app, side-load cover host (persistence) | `c2e62475768c9546efe1da92a55f3bb2a55350eed83241139917aabd1ad25f8a` |
| `zip.exe` (Info-ZIP) | Legit command-line utility | `c50bffbef786eb689358c63fc0585792d174c5e281499f12035afa1ce2ce19c8` |
| Unnamed (x64) | HijackLoader component | `8e8e43a2f0069f081f5ffb77237faebcda9a46e8f8fd0e128500e74bbc9ea3a5` |
| Unnamed (x86) | HijackLoader component | `3594a835ed3dbf80ac460c0e852fa91baa3b17aadff9c3b40c03eff6b34658d2` |
| Unnamed (x64) | HijackLoader component | `729e5965e43ff458f6da901536c9a43be52a3820718e2dd5456150e2d73bb97f` |
| Unnamed (x86) | HijackLoader component | `68bee500e0080f21c003126e73b6d07804d23ac98b2376a8b76c26297d467abe` |
| `tinyutilitymodule.dll` | HijackLoader core module | `b02b8547644bbfe77428e59c5ccec56c412e3c83aec44180e59110189a249956` |
| `AlphVector.exe` (Opera) | Signed app, side-load cover host (Chain B) | `2e26195dd65015aca675d8a17308e9c4cde30b0303f5de80c4ffe35499b67e7f` |
| `msvcp_win.dll` (Microsoft) | Legit runtime dependency | `d7a3b77b3490745dd4f510ff186a6756e12b4787c2dbf75259136f2fcb2d02b9` |
| `opera_elf.dll` | **TROJANIZED** Opera DLL — loads `WebView2Loader.dll` (Chain B) | `81154ee6fba8e9ed282d952e154d907b973526ef06d3d968b9bb950553430106` |
| `WebView2Loader.dll` | HijackLoader (Chain B) | `c208f5d789d03eed155ad1a9f74036c4cab0fe03b8e6c37ff421896ce430d5da` |
| `NeuroManag.exe` (dBpoweramp `dBConfig.exe`) | Signed host — hollowed with Vidar | `40a204d9f4774ba3c320d4f735248267b5db828414aa5e6778383acf357f9738` |

### 1.3 Payloads (unpacked / decrypted)

| File | Role | SHA-256 |
|---|---|---|
| **Vidar v2.1** | Final stealer payload (PE32+ x64, importless) | `debbb3b4fdd9107deec64c46b453b988c5b51a99e006f2c6d1c804b5e2a33991` |
| **SnappyClient RAT** | Final RAT payload (x86) — Chain B | `94b49a66c71e10984746e722be31aaee20b6fa6e5250c460046a0bf626dcb431` |

---

## 2. Network Indicators

### 2.1 Vidar v2.1 — C2 (this campaign)

| Indicator | Type | Notes |
|---|---|---|
| `95.217.245[.]14` | IPv4 | Hardcoded primary endpoint |
| `psh.rzrrent[.]com` | Domain (SNI) | Live C2 |
| `get.rzrrent[.]com` | Domain (SNI) | Live C2 |
| `bou.rzrrent[.]com` | Domain (SNI) | Live C2 |
| `rzrrent[.]com` | Domain | C2 base domain |
| `bou.harussm188[.]top` | Domain | C2 (`*sm188[.]top` cluster) |
| `ggt.gerbongsm188[.]top` | Domain | C2 (`*sm188[.]top` cluster) |
| `hxxps://telegram[.]me/turb00m` | Dead-drop | Telegram fallback resolver (encodes live C2) |
| `hxxps://steamcommunity[.]com/profiles/76561198689449626` | Dead-drop | Steam fallback resolver |

### 2.2 SnappyClient RAT — C2

| Indicator | Type | Notes |
|---|---|---|
| `66.163.113[.]238:3333` | IPv4:port | RAT C2 |
| `66.163.113[.]238:3334` | IPv4:port | RAT C2 |

### 2.3 Reference — Vidar v2.0 C2 (Part 1)

| Indicator | Type |
|---|---|
| `srv.turbo88ku[.]top` | Domain (primary) |
| `hxxps://telegram[.]me/d77xtr` | Dead-drop |
| `hxxps://steamcommunity[.]com/profiles/76561198694566254` | Dead-drop |

---

## 3. Host-Based Indicators

### 3.1 Dropped files & paths

```
%TEMP%\WizardDa42.exe                                  Radmin VPN host (stager)
%TEMP%\NeuroManag.exe                                  dBpoweramp host (hollowed with Vidar)
%TEMP%\VirtualAr.exe                                   Qihoo 360 host (hollowed with SnappyClient)
%TEMP%\<8-hex>.tmp                                     Vidar PE, cache-only / never flushed (run-specific name; observed: 6B4D90.tmp)
%TEMP%\<8-hex>.tmp                                     SnappyClient staging (observed: 7705AC5.tmp)
C:\ProgramData\extadvanced_arm64\                      Loader persistence copy (Radmin + trojanized Qt5Core.dll)
C:\ProgramData\extadvanced_arm64\WizardDa42.exe
C:\ProgramData\Mayanex\                                SnappyClient working directory
%APPDATA%\Roaming\extadvanced_arm64\
%APPDATA%\Roaming\extadvanced_arm64\<RAND>\audio.lib   2nd container (RAND folder is per-run; observed: JWLRGKBWUTOGGGLQFUW)
%APPDATA%\Roaming\service\
%APPDATA%\service\Crisp.exe                            Chain B persistence cover
```

### 3.2 Persistence

```
Startup shortcut:  %APPDATA%\...\Startup\prompt_analyzer_debug.lnk     (relaunches Chain B / SnappyClient at logon)
Scheduled task:    C:\Windows\Tasks\socket_dispatcher_v2.job          (recurring relaunch of Chain B)
```
> Note: the **Vidar** chain plants no persistence of its own (run-once stealer). Persistence belongs to the
> **SnappyClient** path; the loader copy in `C:\ProgramData\extadvanced_arm64\` re-runs the whole chain.

---

## 4. MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 — Spearphishing Attachment |
| Execution | T1204.002 — User Execution: Malicious File |
| Defense Evasion | T1574.002 — DLL Side-Loading |
| Defense Evasion | T1055.012 — Process Hollowing |
| Defense Evasion | T1027 / T1027.003 — Obfuscated Files, Steganography |
| Defense Evasion | T1140 — Deobfuscate/Decode Files or Information |
| Defense Evasion | T1620 — Reflective / in-memory code loading |
| Persistence | T1547.001 — Startup Folder shortcut |
| Persistence | T1053.005 — Scheduled Task |
| Credential Access | T1555.003 — Credentials from Web Browsers |
| Collection | T1005 — Data from Local System; T1113 — Screen Capture |
| Command & Control | T1071.001 — Web Protocols; T1102 — Web Service (dead-drop) |
| Exfiltration | T1041 — Exfiltration Over C2 Channel |
