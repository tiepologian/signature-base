# Operation Turb00 — Vidar Infostealer Campaign

Detection rules and IOCs for **Operation Turb00**, a Vidar infostealer
operation delivered by a custom, **Go loader/crypter**.

The delivered file is a ~3.3 MB Go binary that prints a fake "maze generator" console decoy while
it decrypts and runs a **Vidar** payload entirely in memory. The payload resolves all Windows APIs
by a custom FNV-1a hash, builds its strings at runtime via a small dispatch-table VM, and reads its
C2 configuration from a repeating-XOR–encrypted block. It steals browser credentials/cookies,
crypto wallets, and FTP/SSH client secrets; can download and execute follow-on payloads; and (in
this variant) installs a svchost-loaded persistent DLL. C2 is fronted by Cloudflare, with
**Telegram and Steam dead-drops** used as backup C2 resolvers.

📝 Full technical write-up: **[[link to blog post](https://mrtiepolo.medium.com/operation-turb00-analyzing-and-hunting-a-vidar-campaign-b45481d8cd74)]**

---

## Detection Rules

| File | Type | Tier | What it catches |
|---|---|---|---|
| `vidar_turb00.yar` | YARA | Payload (high precision) | Custom FNV-1a constants, string-VM init constant, S-box, XOR config key, and resolved API-hash dwords. Fires on exposed/unpacked payloads and memory dumps. |
| `vidar_turb00.yar` | YARA | Loader (broad reach) | PE32+/AMD64 + Go build-id + ~3–3.5 MB size band + high-entropy `.data` region + one surviving family code sequence. Pre-execution; some FPs expected. |
| `vidar_turb00_hunting_vt.yar` | YARA | Behaviour (VT Livehunt) | Post-detonation: `/glamis[a-z]*rent/` C2 naming + Telegram-and-Steam dead-drop pair. Survives sample rotation. |
| `vidar_turb00_persistence.yml` | Sigma | Host / persistence | `svchost` service whose `ServiceDll` points into `C:\ProgramData\`, plus the exact `CadenceOptimizer` / `Brn_Agent` / `agt.dll` artifacts. |
| `vidar_turb00_fake_ua_snort.rules` | Snort | Network | The malware's hardcoded **impossible** User-Agents (`Firefox/156.0`, `Edg/147.0.0.0`). Requires plaintext HTTP / TLS inspection. |

---

## Indicators of Compromise

### Samples

| Role | SHA-256 |
|---|---|
| Go loader (stage 1) | `f332b8851b0137ab7fc02a7c64a8b82e62e37b61fc5abf588f25c9797b7ab005` |
| Extracted Vidar payload (stage 2) | `725344564a8c9b0a033e9a5d41369fae5b8503d36e87002e7c064eface927e7b` |
| Sibling Go loader | `7bd5a491f52e28fb1ce93b6ffcd527b1f8dd47d95ab545e12c2692da698a874d` |

### Network — C2 & dead-drops

| Indicator | Role |
|---|---|
| `srv.turbo88ku[.]top` | Primary hardcoded C2 |
| `ggt.glamisrents[.]com` | Family C2 |
| `srv.glamisdunesrentals[.]com`, `ffe.glamisdunesrentals[.]com` | Family C2 |
| `ggt.glamisrent[.]com` | Family C2 |
| `ggt.gerbongsm188[.]top` | Family C2 |
| `amlsentry[.]online` | Family C2 |
| `goturbo88[.]top` / `ggt.goturbo88[.]top` | Family C2 |
| `telegram[.]me/d77xtr` | Telegram dead-drop (backup C2) |
| `telegram[.]me/turb00m` | Telegram dead-drop (backup C2) |
| `steamcommunity[.]com/profiles/76561198694566254` | Steam dead-drop (backup C2) |

### Network — direct-IP C2

```
65.21.96[.]134
65.21.96[.]130
135.181.224[.]78
```

### Network — secondary payload delivery

```
https://netblokirovka[.]asia/files/install.exe
https://netblokirovka[.]asia/files/telemetriawork/telepuz.dll
http(s)://scaleyou.com[.]br/3.exe
http(s)://scaleyou.com[.]br/144.exe
```

### Backend infrastructure & fingerprints

| Indicator | Notes |
|---|---|
| `65.21.96[.]134` | Confirmed C2 backend (Hetzner, FI) |
| `65.21.96[.]131`, `65.21.96[.]135`, `135.181.224[.]79`, `135.181.77[.]214` | Operator TLS-cert fleet |
| Code-signing cert | serial `37C54CED9319769C`, issuer `action[.]com` (invalid signature) |
| Operator TLS cert | serial `b7d2d897adfb46cdbefa997d03bb4841` / thumbprint `ae87b4dab40e1d42fe3558bab959204a915be547` |

## Validated sample cluster (55)

Behaviourally validated members of the campaign's loader cluster. Captured 2026-06-13.

```
f78040944823dda83db96f68fa8a2b6381f737794f23ad43cfe775376914e33a
8d23efc93181cc18f213523a0b39bcc0fd5496756ed6e4adb267aff62ea28628
9339fa65297cbe54e46c61440beadc0c10669488e0b122981a5ab484933523e5
e23eb4d29127401d9804231dc7adbe6dcb526dad19f2f206e6ad94b43817bf3f
205fca4087f80cf3f3f66067e8049d86c4b21cb4ae23dc82bc86025b9c23e173
4a2da20107f60966ffcc67ab1de6088188105194efbdf2038f1dd14a4bbd5c46
79d334f8b91b8a80e5903bd1c3b22a5f0eb503f997171b1ecd622315f6ea6151
d4d1498b325aa6e4b061c34dba6e204d36adc7b0c434246c24759de4dcc39b5a
08c82818bca44e00e3b8bc29f1e6755157aa46421a868607fc455818e6bb7dca
2af1607a2bf33c36fdfd8efae840d135e35c07bbbefe700289334ad104876c42
4e0e5f6018d7d9c2925faef0cdca89dd04a6e72a4967c4eba164159b77f0e1a5
3dae305a8f49979223df7c767dab84f2ccdf101ae45d8fc84ca84324e8cb18f8
18a2403472db07b073bdbeebd41d3ec088236e1e1f3af9d57cbac9633af1e8c7
2af09010211b22731abbc733c648be84f75ac947f919ac895374dd28719c32f6
c33cef7e6e63df7c755c6ce9cbcc672f6c30eff112a9b862f3921aa68ab3959b
1415cbbdaa49b88a29e969b70a205d28e3798797cca392c769750de8a5b14e2a
502815b2a83b2053c218649e3297a652e3cfc105b4ecea5720f3794cdbe2ff39
223a1b132ebd5df43af9b9af963cad9e9899017173a7976ea386518ab621c24d
474e3e8b840f44c53a566f20640374aee8b2c94007ef407888bddaa23ca571dc
3f148ed80088892d2d3e04a25441d4fed467c785a7b1e0aa645db0a7c705b4ad
01ac36c3bbaf292a7a39b8a04c22ca8cd76597ce929d75ce4c950113544c7e61
8998b6887fa8923921030df05d0f77f3e72129da4a638ebf7fef69caedfbd3ac
64c90923bd3990ed08878c99b21d203234d255d33d83f5ea5c48bffabcbd23f0
cc1fa0f7b004b0601f80ccbbb8fd6c80a691b5bdde30ffd376828ca0bcd62efc
e2a7d5be1ad88804dc71518b830bd8eac819a69e9417d0964bf14e82a47699e5
cc966f6b70c632092efdbb6f05f288fb155d976c1bb7fca7495dd1349ff6a9f1
f332b8851b0137ab7fc02a7c64a8b82e62e37b61fc5abf588f25c9797b7ab005
76dab0e3620742541fb2228c84f9a9d20a19e19b6f9085ca0c06063ad76ea0be
fd1b2dc911be109d2fe54c5c20ef527412bb49552dae38e1626d60ec35f2914e
6977a7e5ce6b4bb0f1e000baea51272ed081fbdd5c1e53454c4559d6653df843
2015a32873ca95b3dbea6836c8498b2753a9473f6933397640152a52a406b2b1
f6a876bfd96884a892f55c396c668f7af487099a396d1d0ddd9fe29ea5c3884d
3fe5c283f6357df553cfbd9d68397a6cc1e5c32d3f510a99cf107a2af0657d09
9007630f6ca31b4206905d3f5bad94c2b260bd4a98ce8f5270a796167ea37092
1186f5bab9afb46d5527a9772b29ea278d41804c0f753278979bd7be8bd9179e
76422efe5c8bf04cdef9ac9fb7117a72680a6273f44b492ba227d2f70778af51
52f471a1df204c3b3c345014dbc3dd505769cf36c8f823a608e149e4f2eb4867
aff32c5d4cb3f137a94ad3b39548cefb786c9e9d440e8a2e1ffa0b22312a0401
d570c33a5dce595138f6c25b6a1ecd7b4e474e6f440f44a2831aa5c84c1016f3
1c8d29edd55186c65475f8abc732a1e7c6b05fb28d8e3207cd13bf4a2203ea9e
e6dbab6ac96ab24267f4db82d25f5ceb0113578914bd936b09efab132f5ec07b
97cbe593421cffba1fbd5969bca89beb416e0f47971026297454f86e148426b8
d8a463eb776156848993c90ad9201a56fe34cfb50fd404246a703b71e5107ae4
df6832dfba5c046e2c199bfdfa1eee5821ea0c4459d0a14780c59b2c49d40673
c60daf3e901801a88d875bfedb64ac9ae6c5726e533fce9076e2edc68d502d2a
7c69d70092676725b6e9269e08f842b22a21eff319240a31b2dfc44147d05d05
c3d3d02c884f1a4964fe5c01b2d8c21f77027388d54082162f3e35b8a72c0a68
9e6629b48b633d41ab34bcd7a9c2ed7c64f78699debcc7a127ffa85091e0ab9c
dce4751bbb019e6a19ee1c663a1fae9bc434d9467e0baf7aa87e873b77617e1e
15d191fda1c045184d5ff6417fdc0a54a1e6c918302d1013f88c7ae193e7b9fa
ebb0262445f896c2eef8882ff7ee569012cf00bbdf6d742a078a971da3f8262a
cc26b0403831530bdc1b90cc76329b595155611ecc5931a392f281d311762451
63aea327fe9c5da94d8170396d902f6e8f4bf185d8108b93dc3ca1f5996d749b
6d0f7cc3d9e8063dfa0ebbbaea7ef480344f98f83fb267b7c5bdf0d6ff2c5f9a
feb512386d2092387ad09fff5ec225a15359334cec582fe8c206e2cb0babaef0
```
