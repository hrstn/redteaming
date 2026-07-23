# Extension-Kit

Extension Kit for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)

> **Note:** this is a vendored copy of
> [Adaptix-Framework/Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)
> (GPLv3, see `LICENSE`) with its `.git` history removed. All upstream suites below are
> intact and unmodified. On top of upstream it adds the **`AI-BOF`** suite (OSAI / AI-300)
> and the **`pth`** pass-the-hash BOF in `LateralMovement-BOF` — see the corresponding
> sections below.

# Installation

```
# Ubuntu/Kali
apt install g++-mingw-w64-x86-64-posix  gcc-mingw-w64-x86-64-posix  mingw-w64-tools

# Arch
pacman -Syu mingw-w64-x86_64-gcc mingw-w64-x86_64-gcc-libs
```

Building modules via make

```bash
git clone https://github.com/Adaptix-Framework/Extension-Kit
cd Extension-Kit
make
```

Load all modules in AdaptixC2 client: **Main menu** -> **AxScript** -> **Script manager**. 

![](./_img/01.png)

**Context menu** -> **Load new** and select the _extension-kit.axs_ file.

# Modules

## AI-BOF *(custom addition — not in upstream)*

BOFs that help AdaptixC2 beacons **find AI content and solve the lab tasks** in the
OffSec OSAI (AI-300) course. All run **in-process** (zero child processes) — OPSEC
for SIEM-monitored labs. 15 commands: `aiHunter`, `credsMem`, `credsLaunch`,
`envScraper`, `aiSvcProbe`, `shareWalk`, `poisonStage`, `configDump`, `logTail`,
`kubeHunter`, `tokenizerSwap`, `picklePlant`, `gitMine`, `vectorExport`,
`sessionBrute`. [More details](./AI-BOF/README.md)

## AD-BOF

A BOFs that contains common enumeration and attack methods for Windows Active Directory.

![](./AD-BOF/_img/01.png)

![](./AD-BOF/_img/02.png)

![](./AD-BOF/_img/03.png)

![](./AD-BOF/_img/04.png)

![](./AD-BOF/_img/05.png)

## Creds-BOF

BOF tools that can be used to harvest passwords [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Creds-BOF/README.md)

![](./Creds-BOF/_img/01.png)



## Elevation-BOF

BOFs for context elevation. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Elevation-BOF/README.md)

![](./Elevation-BOF/_img/01.png)



## Execution-BOF 

BOFs for inline execution. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Execution-BOF/README.md)

![](./Execution-BOF/_img/01.png)



## Injection-BOF

Beacon Object Files for injects desired shellcode into target process. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Injection-BOF/README.md)

![](./Injection-BOF/_img/01.png)



## LateralMovement-BOF

BOFs for lateral movement with the specified method. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/LateralMovement-BOF/README.md)

![](./LateralMovement-BOF/_img/01.png)

> **`pth`** *(custom addition — not in upstream)* — Pass-the-Hash make-token /
> run-binary. Mints a network-logon token from an NT hash alone via `LsaLogonUser` +
> `MSV1_0_LM20_LOGON` + a self-computed NTLMv2 response (no lsass patching, no driver,
> Credential-Guard-safe, admin-only). `pth <user> <domain> <nthash> [binary]`.
> [More details](./LateralMovement-BOF/pth/README.md)



## Process-BOF

BOFs that provide situational awareness of processes, modules, and services. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Process-BOF/README.md)

![](./Process-BOF/_img/01.png)



## Postex-BOF

This extension allows you to customize the Beacon Object File (BOF) for future use. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/Postex-BOF/README.md)

![](./Postex-BOF/_img/01.png)



## SAL-BOF

Situation Awareness Local BOFs. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/SAL-BOF/README.md)

![](./SAL-BOF/_img/01.png)



## SAR-BOF

Situation Awareness Remote BOFs. [More details](https://github.com/Adaptix-Framework/Extension-Kit/blob/main/SAR-BOF/README.md)

![](./SAR-BOF/_img/01.png)



# CONTRIBUTING

Please pushing сhanges to **dev** branch. Otherwise, changes will be made manually in the **dev** branch.
