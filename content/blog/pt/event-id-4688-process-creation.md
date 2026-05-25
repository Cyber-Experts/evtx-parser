---
title: "Event ID 4688 explicado: auditoria de criação de processos do Windows para DFIR"
description: "4688 é o registro base do SO para criação de processo — desde que command-line auditing esteja ligado. Eis o que ele contém, como difere do Sysmon 1, e os padrões de triagem que ganham o pão."
date: "2026-05-24"
---

O Event ID **4688** — "A new process has been created" — dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) toda vez que um processo é lançado. É o mais próximo que o SO base chega da telemetria que o [Sysmon event 1](/pt/blog/sysmon-event-id-1-process-create) fornece — e em hosts onde Sysmon não está implantado, é a única fonte de `CommandLine` que você tem. Em um ambiente configurado corretamente, toda criação de processo é um desses registros. Leia-o bem e você consegue responder "o que rodou" sem nunca abrir um EDR.

## Ligando isso (porque o padrão é meio-cego)

Por padrão, 4688 está habilitado mas `CommandLine` **não** é capturado. Sem `CommandLine`, o registro te diz um caminho de binário, um PID, um PID pai — e nada sobre os argumentos. Para triagem isso é quase inútil: `powershell.exe` é OK; `powershell.exe -enc SQBFAFgA…` não é.

A correção é uma configuração de Group Policy:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

Ou o equivalente em registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Uma vez definido, todo 4688 carrega o campo `CommandLine` completo. O custo é volume de log; o benefício é toda a superfície de investigação que existe abaixo do nome do binário. Ligue.

Você também precisa que a política de auditoria subjacente esteja ligada: `auditpol /set /subcategory:"Process Creation" /success:enable`. Muitos hosts têm policy ligada mas command-line desligado — verifique ambos.

## O que o registro contém

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

Campos que dirigem toda investigação:

- **`CommandLine`** — argv completo (quando o GPO está ligado).
- **`NewProcessName`** — o caminho do binário. Combinado com `CommandLine`, essa é a execução completa.
- **`ParentProcessName`** — o processo chamador. Office → cmd, browser → powershell, services → unsigned.exe são as cadeias clássicas.
- **`SubjectUserName` / `SubjectLogonId`** — quem o lançou, sob qual sessão. `SubjectLogonId` pivota de volta para o [4624](/pt/blog/understanding-event-id-4624) que criou a sessão e para outros registros na mesma sessão.
- **`TokenElevationType`** — `%%1936` Default (sem elevação), `%%1937` Full (consent UAC concedido), `%%1938` Limited (filtrado). Um `1937` em uma sessão não-admin é uma transição de privilégio que merece atenção.
- **`MandatoryLabel`** — SID de integrity level. `S-1-16-12288` é High (elevado), `8192` é Medium, `16384` System.

## 4688 vs. Sysmon 1

Eles se sobrepõem; não são idênticos.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sim (se GPO ligado) | Sim |
| Image / NewProcessName | Sim | Sim |
| Imagem pai | Sim (caminho) | Sim (caminho + CommandLine) |
| ParentCommandLine | Não | Sim |
| ImageHash (SHA/MD5/IMPHASH) | Não | Sim |
| ProcessGuid (estável entre hosts) | Não (só PIDs, reutilizados) | Sim |
| User SID + nome | Sim | Sim |
| Logon ID | Sim | Sim |
| CurrentDirectory | Não | Sim |
| Integrity level | Sim | Sim |
| Disponível sem instalar | Sim | Requer Sysmon |

Quando ambos estão presentes, o [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) é o registro mais rico — `ParentCommandLine`, image hashes, ProcessGuid para cadeias pai-filho estáveis. Quando só o 4688 está presente, você constrói cadeias com PIDs (que o Windows reutiliza), então uma timeline longa pode incluir false matches; sempre cruze links pai-filho contra timestamps.

## Os padrões de triagem

Em um corpus de registros 4688, esses padrões ganham o pão:

1. **Office → shell**: `ParentProcessName` terminando em `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` ou `mshta.exe`, com `NewProcessName` sendo `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` ou `regsvr32.exe`. Apps de documento spawnando shells é a cadeia clássica de macro / phishing.
2. **PowerShell encodado**: `NewProcessName` terminando em `powershell.exe` e `CommandLine` casando com `-enc`, `-encodedcommand`, `-e ` (única letra), `frombase64string`, `iex ` ou `invoke-expression`. Decodifique o payload; cruze com o [registro 4104 de scriptblock](/pt/blog/powershell-4104-scriptblock) para a mesma sessão.
3. **LOLBins de caminhos graváveis por usuário**: binários Microsoft assinados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lançando de `C:\Users\`, `%TEMP%` ou `C:\ProgramData\`. Uso legítimo deles é raro nesses locais.
4. **Órfãos de service host**: `svchost.exe` com `ParentProcessName` ≠ `services.exe` (ou `wininit.exe` para boot bem inicial). `svchost` real é sempre spawnado por `services.exe`; impostores se destacam.
5. **Binários renomeados**: `NewProcessName` terminando em algo neutro (`update.exe`, `svc.exe`, `data.exe`) sob caminhos não padrão. Combine com o campo `OriginalFileName` do Sysmon 1 quando disponível — esse é o que pega PsExec renomeado, Mimikatz, etc.

## Exemplo de regra Sigma (office → shell)

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## Exemplo de KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Mapeamento ATT&CK

O grosso da cobertura de detecção de 4688 cai sob **T1059 — Command and Scripting Interpreter** e suas sub-técnicas (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). Padrões LOLBin mapeiam para **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Cadeias Office → shell correspondem a **T1566.001 — Phishing: Spearphishing Attachment** combinado com T1059. Detecções de binário renomeado caem sob **T1036.003 — Masquerading: Rename System Utilities**.

## Falsos positivos (leia isto antes de alertar)

- **Agentes de software-update** legitimamente spawnam shells: Chocolatey, WinGet, wrappers MSI de vendors. Whitelist por `SubjectUserSid` (LocalSystem) mais padrões estáveis de `ParentProcessName` em vez de contas de usuário.
- **Scanners de vulnerabilidade e produtos EDR** geram árvores de processo que se parecem exatamente com um atacante fazendo recon: net.exe, whoami.exe, systeminfo.exe. Marque IPs / hosts de scanner e exclua.
- **Boxes Citrix / RDS multi-sessão** veem cadeias legítimas `runas /netonly` para acesso cross-domain. Investigue o usuário, não o padrão.
- **Logon scripts** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) disparam em todo logon e aparecerão como uma cadeia recorrente. Identifique e baseline antes de alertar.

## O que 4688 não te diz

Sem hash de arquivo. Sem `ParentCommandLine`. Sem `ImageLoaded` (injeção de DLL não é uma criação de processo). Sem comportamento de rede. Para isso você precisa do [Sysmon event 1](/pt/blog/sysmon-event-id-1-process-create) (o 4688 mais rico), Sysmon 7 (image load), Sysmon 3/22 (network/DNS) e, onde presente, os dados comportamentais de um EDR. 4688 é o piso da visibilidade de processo — o mínimo que todo host Windows deveria ter. Não é substituto para EDR + Sysmon apropriados em hosts que importam.

## Onde 4688 se encaixa em uma timeline

Para uma cadeia típica de pós-exploração em um host sem Sysmon, sua timeline lerá:

1. [**4624**](/pt/blog/understanding-event-id-4624) — logon inicial, LogonType 3 de um IP externo.
2. **4624** — segundo logon, LogonType 9 (`runas /netonly`) sob o mesmo `SubjectLogonId` — pivot de credencial.
3. **4688** — `powershell.exe -enc ...` sob essa sessão.
4. [**4104**](/pt/blog/powershell-4104-scriptblock) — corpo de script decodificado, buscando um payload de segundo estágio.
5. **4688** — binário de segundo estágio rodando de `%TEMP%`.
6. [**7045**](/pt/blog/service-creation-event-id-7045) — serviço instalado para persistência.

Seis registros contam a história inteira. Os PIDs em (3) e (5) conectam via `ProcessId`/`NewProcessId` do 4688 — mas verifique por timestamp porque o Windows recicla PIDs. Com Sysmon presente, a cadeia `ProcessGuid` substitui esse match frágil.
