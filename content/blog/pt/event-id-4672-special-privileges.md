---
title: "Event ID 4672 explicado: detetar logons privilegiados no Windows"
description: "O 4672 dispara sempre que um logon recebe privilégios sensíveis como SeDebugPrivilege ou SeTcbPrivilege. Lê-lo como o sinal 'este logon é equivalente a admin' e o resto da política de auditoria encaixa."
date: "2026-05-24"
---

O Event ID **4672**, "Foram atribuídos privilégios especiais a um novo logon", dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que uma sessão de logon recebe um de um conjunto fixo de privilégios Windows sensíveis. Na prática, cada logon de administrador bem-sucedido produz um 4672, escrito imediatamente após o correspondente [4624](/pt/blog/understanding-event-id-4624). Na maioria das workstations o 4672 é raro. Nos domain controllers e jumphosts de admin é constante. Essa assimetria é o que o torna útil.

Se filtrar Security por um campo esta semana, corra "todos os 4672 nos últimos sete dias". É a query mais barata de "mostra-me cada sessão privilegiada no parque" que pode escrever.

## Onde dispara

No host onde o logon realmente aconteceu, igual ao [4624](/pt/blog/understanding-event-id-4624). Um logon de rede para `SERVER01` produz o 4624 e o 4672 em `SERVER01`, não na workstation de origem. Para detetar algo do 4672 em escala, precisa de recolha de Security pelo menos dos servidores e DCs. Workstations admin e jumphosts se puder pagar o volume.

## O que o registo contém

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

- `SubjectLogonId`. O mesmo `LogonId` do [4624](/pt/blog/understanding-event-id-4624) correspondente. Este é o seu pivot. Cada 4672 liga exatamente um 4624 (e cada registo subsequente nessa sessão) ao conjunto de privilégios que o logon recebeu.
- `PrivilegeList`. O saco de privilégios real. O Windows regista apenas os privilégios "sensíveis" definidos na política de auditoria. Um logon pode ter mais privilégios do que o registo mostra. Os omitidos (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc.) são não-relevantes para segurança e são podados deste registo de propósito.
- `Subject*`. A quem pertence o logon. Quase sempre idêntico ao 4624 correspondente.

Não há `IpAddress`, nem `LogonType`, nem `WorkstationName` no próprio 4672. Para os obter, junta-se ao 4624 via `SubjectLogonId`. Analistas que tentam alertar só com o 4672 frequentemente perdem isto e acabam com registos que não conseguem enriquecer.

## Os privilégios e o que significam

| Privilégio | Nome de exibição | Porque importa |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Ler/escrever a memória de qualquer processo, incluindo `lsass.exe`. O Mimikatz precisa disto. |
| `SeTcbPrivilege` | Act as part of the OS | Efetivamente `LocalSystem`. Devia aparecer apenas para LocalSystem. |
| `SeImpersonatePrivilege` | Impersonate a client after auth | O privilégio usado pela família Potato (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process token | Ferramentas de impersonation de token. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | Contorna ACLs para ler/escrever ficheiros arbitrários incluindo hives do registo. `reg save HKLM\SAM` funciona com estes. |
| `SeTakeOwnershipPrivilege` | Take ownership | Sobrepõe ACLs de ficheiro. |
| `SeLoadDriverPrivilege` | Load drivers | Necessário para BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Manage audit log | Ler ou limpar Security. Necessário para disparar o [1102](/pt/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware | Bootkits, adulteração EFI. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Comum em quase todos os logons. Não é sinal de triagem. |

Alguns são esperados em cada logon admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Outros devem ser mais raros (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). O sinal é o privilégio *inesperado* na conta *errada*.

## Os padrões

### Estabelecer a baseline de quem recebe 4672

Num parque saudável, os produtores de 4672 são um conjunto pequeno e conhecido:

- `LocalSystem` (S-1-5-18). Cada host, todo o tempo, no arranque de serviços.
- `NetworkService` (S-1-5-20). Comum em servidores a correr serviços com impersonation.
- Um punhado de administradores, identificados por SID em vez de nome.

Qualquer outro é um novo admin de que não sabia, um evento de escalada de privilégios ou uma conta mal configurada.

A query de baseline mais barata: `SubjectUserSid` distintos do 4672 nos últimos 30 dias, ordenados por frequência. Tudo fora do top N vale uma olhada.

### SeImpersonatePrivilege numa conta sem privilégio

Se um 4672 mostrar `SeImpersonatePrivilege` numa conta que não é admin e não é um SID `*Service`, é quase de certeza uma escalada Potato. Estes exploits dão a um chamador `IIS_IUSRS` ou com token de serviço o `SYSTEM`. O 4672 dispara *à medida que o privilégio é adquirido*. Isto é mais cedo do que qualquer processo visível spawned com o novo privilégio.

### SeDebugPrivilege sem grupo admin

`SeDebugPrivilege` é concedido a admins locais por política. Numa conta não-admin, ou a política foi modificada (geralmente por um atacante para permitir acesso a LSASS) ou um atacante injetou-se num processo admin.

### Logon privilegiado fora de horas

Um 4672 para uma conta admin real às 03:00 de um domingo é o alerta fora-de-horas mais barato que existe. Combine com o `LogonType` e `IpAddress` do 4624 correspondente para contexto.

### Drift em conta de serviço

Uma conta de serviço que historicamente só dispara `SeImpersonatePrivilege` e `SeAssignPrimaryTokenPrivilege` a produzir subitamente 4672s com `SeBackupPrivilege` e `SeDebugPrivilege` significa que alguém mudou as suas memberships de grupo. Combine com 4732 ou 4728 para encontrar a mudança de membership.

## Sigma: SeDebugPrivilege num não-admin

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
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Afine `filter_known_admins` por ambiente. Algumas lojas usam uma lista de SIDs em vez de um padrão de nome.

## KQL: escalada da família Potato

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

## Splunk: baseline de logons admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Corra isto semanalmente. As anomalias aparecem como contas novas no top 50.

## Mapeamento ATT&CK

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege em contas sem privilégio.
- T1003.001 LSASS Memory. SeDebugPrivilege é a pré-condição.
- T1068 Exploitation for Privilege Escalation. Qualquer ganho inesperado de privilégio.
- T1078 Valid Accounts. 4672 para contas admin legítimas a partir de origens invulgares.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege é necessário para chamar `ClearEventLog`. Um 4672 a carregar este privilégio imediatamente antes de [1102](/pt/blog/event-id-1102-cleared-log) é o rasto de migalhas.

## Falsos positivos que parecem ataques

- Software de backup (Veeam, Commvault) dispara rotineiramente 4672 com `SeBackupPrivilege` + `SeRestorePrivilege` a partir de contas de serviço. Baseline por SID da conta de serviço.
- Agentes de monitorização (SCOM, coletores WMI personalizados) disparam 4672 amplamente. Marque o host do agente.
- Alguns runners de scripts de logon sob contextos privilegiados produzem cadeias de 4672 no momento do logon.
- Hyper-V, VMM, hosts de contentores geram 4672 denso a partir de `LocalSystem` e contas de serviço geridas.

O sinal é o produtor *novo*, não o *recorrente*. Um produtor de 4672 que dispara diariamente há um ano é configuração. Um que acabou de aparecer esta semana é a pista.

## O que o 4672 não lhe diz

- Sem informação de processo. Vê a concessão de privilégio, não o que o processo privilegiado fez. Para seguir em frente, pivote `SubjectLogonId` para registos [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) na mesma sessão.
- Sem IP de origem diretamente. Junte-se a [4624](/pt/blog/understanding-event-id-4624) via `SubjectLogonId`.
- Nem toda a ação privilegiada. Apenas a *concessão no logon* é registada. Usos subsequentes (e.g. `RtlAdjustPrivilege` a alternar `SeDebugPrivilege` on/off) produzem registos 4673/4674, não outro 4672.
- Falha-se se a auditoria Special Logon estiver off. A sub-política de auditoria é *Audit Special Logon*. Por defeito ligada em Windows moderno, mas vale a pena verificar.

## Onde o 4672 encaixa numa timeline

A cadeia clássica de escalada-e-limpeza:

1. [4624](/pt/blog/understanding-event-id-4624). LogonType 3 de um IP controlado pelo atacante, utilizador low-priv.
2. *(silencioso)*. Escalada baseada em SeImpersonatePrivilege (PrintSpoofer ou similar).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege concedidos a uma nova sessão de logon a correr como LocalSystem. Escalada visível aqui.
4. [4688](/pt/blog/event-id-4688-process-creation). `cmd.exe` ou `powershell.exe` como SYSTEM via token impersonated.
5. [4104](/pt/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` ou `comsvcs.dll MiniDump` contra LSASS. SeDebugPrivilege é o que faz isto funcionar.
6. [1102](/pt/blog/event-id-1102-cleared-log). Log de Security limpo. SeSecurityPrivilege do passo 3 permitiu isto.
7. **4672**. Segunda sessão privilegiada como domain admin extraído da memória LSASS.

Os 4672s nos passos 3 e 7 são os pontos de deteção mais baratos. Sem eles está a montar a impersonação só a partir de eventos de processo. Mais lento, mais fácil de falhar.

## Leitura adicional

- [Documentação Microsoft do 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
