---
title: "Event ID 4672 explicado: detectando logons privilegiados no Windows"
description: "4672 dispara quando um logon recebe privilégios sensíveis como SeDebugPrivilege ou SeTcbPrivilege. Leia como o sinal 'este logon é admin-equivalente' e o resto da auditoria se encaixa."
date: "2026-05-24"
---

O Event ID **4672** — "Special privileges assigned to new logon" — dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) toda vez que uma sessão de logon recebe um de um conjunto fixo de privilégios sensíveis do Windows. Na prática isso significa: todo logon bem-sucedido equivalente a administrador produz um 4672, imediatamente após o [4624](/pt/blog/understanding-event-id-4624) correspondente. Na maioria das estações, 4672 é raro; em domain controllers e admin jumpboxes, é constante. Essa assimetria é o que o torna útil.

Se você só filtra registros Security por um campo, "me dê todos os 4672s da última semana" é a query mais barata de "mostre toda sessão privilegiada no ambiente" que você pode rodar.

## Onde dispara

Sempre no host onde o logon de fato aconteceu — igual ao [4624](/pt/blog/understanding-event-id-4624). Um logon de rede em `SERVER01` produz o 4624 e (se privilegiado) o 4672 em `SERVER01`, não na estação de origem. Para detectar qualquer coisa de 4672 em escala, você precisa de coleta Security de servidores e DCs no mínimo; de estações de admin e jumphosts se puder bancar o volume.

## O que o registro contém

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

Os campos:

- **`SubjectLogonId`** — o mesmo `LogonId` que aparece no [4624](/pt/blog/understanding-event-id-4624) correspondente. Esse é seu pivot: cada 4672 amarra exatamente um 4624 (e cada registro subsequente naquela sessão) ao conjunto de privilégios que aquele logon recebeu.
- **`PrivilegeList`** — o bag de privilégios efetivo. O Windows registra aqui apenas um conjunto fixo de privilégios "sensíveis" (definidos na política de auditoria); um logon pode deter mais privilégios do que o registro mostra. Os omitidos — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc. — são não relevantes para segurança e são podados deste registro de propósito.
- **`Subject*`** — a quem o logon pertence. Quase sempre idêntico aos mesmos campos no 4624 correspondente.

Não há `IpAddress`, `LogonType` nem `WorkstationName` no próprio 4672. Para tê-los, faça o join com o 4624 via `SubjectLogonId`.

## Os privilégios e o que significam

| Privilégio | Nome de exibição | Por que importa |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Ler/escrever a memória de qualquer processo — incluindo `lsass.exe`. Mimikatz precisa disso. |
| `SeTcbPrivilege` | Act as part of the operating system | Efetivamente `LocalSystem`. Deve aparecer apenas para o próprio LocalSystem. |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | O privilégio usado pelas famílias de exploit baseadas em `SeImpersonatePrivilege` (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Ferramental de token-impersonation. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | Bypass de ACLs para ler/escrever arquivos arbitrários — incluindo registry hives. `reg save HKLM\SAM` funciona com isso. |
| `SeTakeOwnershipPrivilege` | Take ownership of files | Sobrescrever ACLs de arquivo. |
| `SeLoadDriverPrivilege` | Load and unload device drivers | Requerido para ataques BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Manage auditing and security log | Ler/limpar o Security event log. Necessário para disparar [1102](/pt/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkits, tampering de EFI. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Comum na maioria dos logons; não é sinal de triagem. |

Alguns desses você espera em todo logon de admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Outros deveriam ser mais raros (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). O sinal está no privilégio *inesperado* aparecendo na conta *errada*.

## Os padrões de triagem

### 1. Faça baseline de quem recebe 4672

Em um ambiente saudável, os produtores de 4672 são um conjunto *pequeno e conhecido*:

- `LocalSystem` (S-1-5-18) — todo host, o tempo todo, no startup de serviços.
- `NetworkService` (S-1-5-20) — comum em servidores rodando serviços capazes de impersonation.
- Um punhado de administradores, identificados por SID em vez de nome.

Qualquer outro gerando um 4672 é ou: um novo admin que você não conhecia, um evento de escalada de privilégio, ou uma conta mal configurada.

A query de baseline mais barata: `SubjectUserSid` distintos de 4672 nos últimos 30 dias, ordenado por frequência. Qualquer coisa fora dos top N produtores merece uma olhada.

### 2. SeImpersonatePrivilege em uma conta sem privilégios

Se um 4672 mostra `SeImpersonatePrivilege` em uma conta que não é admin e não é um SID `*Service`, é quase certamente uma escalada da família "Potato" (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). Esses exploits dão a um chamador `IIS_IUSRS` ou de token de serviço `SYSTEM`. O 4672 dispara *no momento em que o privilégio é adquirido* — antes de qualquer processo visível spawnado com o novo privilégio.

### 3. SeDebugPrivilege sem grupo de admin

`SeDebugPrivilege` é concedido a admins locais por política. Vê-lo em uma conta não-admin é sinal de que a política foi modificada — geralmente por um atacante para habilitar acesso a LSASS — ou que um atacante injetou em um processo de admin.

### 4. Logon privilegiado fora do horário comercial

Um 4672 para uma conta admin real às 03h de domingo é o alerta mais barato de "atividade de admin fora de horário" que existe. Combine com `LogonType` e `IpAddress` do 4624 correspondente para contexto.

### 5. Drift de service account

Uma service account que historicamente só dispara `SeImpersonatePrivilege` e `SeAssignPrimaryTokenPrivilege` de repente produzindo 4672s com `SeBackupPrivilege` e `SeDebugPrivilege` significa que alguém mudou suas memberships de grupo. Combine com 4732/4728 para encontrar a mudança de membership.

## Exemplo de regra Sigma — SeDebugPrivilege em não-admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Ajuste `filter_known_admins` por ambiente; algumas operações usam uma lista de SIDs em vez de um padrão de nome.

## Exemplo de KQL — escalada da família Potato

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Exemplo de Splunk — baseline de logons de admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Rode isso semanalmente; anomalias aparecem como novas contas no top 50.

## Mapeamento ATT&CK

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**: SeImpersonatePrivilege em contas não privilegiadas.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: SeDebugPrivilege é a pré-condição.
- **T1068 — Exploitation for Privilege Escalation**: qualquer ganho de privilégio inesperado.
- **T1078 — Valid Accounts**: 4672 para contas admin legítimas vindas de origens incomuns.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: SeSecurityPrivilege é necessário para chamar `ClearEventLog`; um 4672 com esse privilégio imediatamente antes de [1102](/pt/blog/event-id-1102-cleared-log) é a trilha de migalhas.

## Falsos positivos que parecem exatamente ataques

- **Software de backup** (Veeam, Commvault) rotineiramente dispara 4672 com `SeBackupPrivilege` + `SeRestorePrivilege` de service accounts. Baseline por SID de service account.
- **Agentes de monitoramento** (SCOM, coletores WMI customizados) que leem dados security-relevant disparam 4672 amplamente. Marque o host do agente.
- **Alguns runners de logon-script** sob contextos privilegiados produzem cadeias de 4672 no momento do logon.
- **Hosts Hyper-V / VMM / container** geram tráfego denso de 4672 de `LocalSystem` e managed service accounts.

O sinal está no produtor *novo*, não no *recorrente*. Um produtor de 4672 que dispara diariamente há um ano é configuração; um que apareceu esta semana é a pista.

## O que 4672 não te diz

- **Sem informação de processo**: você vê a concessão do privilégio, não o que o processo privilegiado fez. Para acompanhar daí em diante, pivote `SubjectLogonId` para registros [4688](/pt/blog/event-id-4688-process-creation) / [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) na mesma sessão.
- **Sem IP de origem** diretamente: você tem que fazer join com [4624](/pt/blog/understanding-event-id-4624) via `SubjectLogonId` para obtê-lo.
- **Nem toda ação privilegiada**: apenas a *concessão no logon* é registrada. Usos subsequentes (ex., `RtlAdjustPrivilege` ligando/desligando `SeDebugPrivilege`) produzem registros 4673/4674, não outro 4672.
- **Perdido se auditoria de Special Logon estiver desligada**: a subcategoria de auditoria é *Audit Special Logon*, que deve estar habilitada para success events. Está ligada por padrão no Windows moderno, mas vale verificar.

## Onde 4672 se encaixa em uma timeline

A cadeia escolar de escalada-e-limpeza:

1. [**4624**](/pt/blog/understanding-event-id-4624) — LogonType 3 de um IP controlado pelo atacante, usuário low-priv.
2. *(silencioso)* — escalada baseada em `SeImpersonatePrivilege` (PrintSpoofer ou similar).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` concedidos a uma nova sessão de logon rodando como `LocalSystem`. **Escalada visível aqui.**
4. [**4688**](/pt/blog/event-id-4688-process-creation) — `cmd.exe` ou `powershell.exe` rodando como SYSTEM via o token impersonado.
5. [**4104**](/pt/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` ou `comsvcs.dll MiniDump` contra LSASS — SeDebugPrivilege é o que faz isso funcionar.
6. [**1102**](/pt/blog/event-id-1102-cleared-log) — Security log limpo. SeSecurityPrivilege do passo 3 habilitou isso.
7. **4672** — segunda sessão privilegiada como um domain admin extraído da memória do LSASS.

Os 4672s nos passos 3 e 7 são os pontos de detecção mais baratos da cadeia. Sem eles você está montando impersonation a partir de eventos de processo apenas — mais lento e mais fácil de perder.
