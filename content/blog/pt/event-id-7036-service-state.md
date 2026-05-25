---
title: "Event ID 7036 explicado: mudanças de estado de serviço para triagem DFIR"
description: "7036 dispara toda vez que um serviço inicia ou para. Combinado com 7045 confirma se a persistência de fato rodou — e sozinho revela abuso de serviço, defense evasion e anomalias de boot."
date: "2026-05-24"
---

O Event ID **7036** — "The {service} service entered the {state} state" — dispara no [canal `System`](/pt/blog/what-is-an-evtx-file) toda vez que o Service Control Manager (SCM) vê uma transição de serviço. Cada start, stop, pause e resume produz um. Por si só é alto volume e fácil de descartar; combinado com [7045](/pt/blog/service-creation-event-id-7045) (service installed) é a diferença entre *um backdoor foi instalado* e *um backdoor foi instalado e rodou*.

Para resposta a incidente, este é o registro mais barato de "executou?" que o SO te dá.

## Onde vive

Sempre no **canal `System`** no host onde o serviço rodou. Sem envolvimento do DC, sem encaminhamento por canal para se preocupar — está bem ali no `System.evtx`. O provider é `Service Control Manager`.

## O que o registro contém

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

Só isso. Dois parâmetros e uma tag binária — muito menor que a maioria dos registros Security, razão pela qual analistas pulam.

- **`param1`** — o *display name* do serviço (não o short name). `Background Intelligent Transfer Service` aqui é o nome user-facing de `BITS`. Para pivotar para a definição do serviço você frequentemente precisará do short name; o SCM também o estampa em `Binary` como um blob codificado em UTF-16 (o `42 00 49 00 54 00 53 00` aqui decodifica para `BITS`).
- **`param2`** — o novo estado: `running`, `stopped`, `paused`, `resumed`, ou um de um punhado de intermediários pendentes (`start pending`, `stop pending`). As transições `running` e `stopped` são as que a maioria das regras usa como chave.

Não há `AccountName`, `ImagePath` nem `ProcessId` — 7036 te diz *o que* mudou de estado, não *quem* disparou a mudança. Para o porquê, combine com outros registros (veja abaixo).

## 7036 vs 7045 vs 7035 vs 7034

Quatro eventos relacionados a serviço do canal System são confundidos constantemente:

| Evento | Quando | O que te dá |
|---|---|---|
| **7045** | Serviço instalado | Display name, short name, `ImagePath`, `AccountName`, `StartType`. O ponto de persistência. |
| **7036** | Start/stop de serviço | Apenas display name. O ponto de execução. |
| **7035** | Controle de serviço enviado | Quem iniciou o start/stop (SID), qual controle foi enviado. Raramente ligado por padrão; valioso quando está. |
| **7034** | Serviço crashed inesperadamente | Serviço que terminou sem um stop limpo. Ação de recovery. |

O padrão importa: **um 7045 seguido segundos depois por um 7036 `running` para o mesmo display name é a sequência escolar "instalado e rodou".** Um 7045 *sem* um 7036 correspondente significa que o serviço foi registrado mas nunca executado — ou o atacante limpou, o instalador abortou, ou o start foi adiado.

## Os padrões de triagem

### 1. Verificação de persistência — combine com 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Três registros, um evento de execução lateral PsExec. O par de 7036 te diz que o serviço realmente rodou (não só foi instalado). Para um backdoor *persistente* o segundo 7036 (stopped) pode estar ausente ou pode aparecer horas/dias depois quando o host reinicia.

Um 7045 sem 7036 `running` em minutos é uma anomalia própria — investigue por que o install não disparou. Causas comuns: o instalador está stageado para próximo reboot, o serviço foi setado para manual start e o atacante ainda não tinha disparado, ou o start falhou (procure erros 7034 / 7000).

### 2. Sinal de defense-evasion — parando serviços de segurança

O padrão mais abusado: um atacante para `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` ou o serviço de um produto EDR. Cada um gera um 7036 `stopped` para o display name correspondente. Se tampering de política de auditoria / Defender está sendo tentado, este é um dos registros que sobrevive.

Os nomes para alertar (display names; variam por versão de Defender / EDR):

- `Windows Defender Antivirus Service` → serviço `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- Qualquer coisa casando com `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Um 7036 `stopped` para qualquer destes — especialmente fora de uma janela de manutenção agendada — deveria ser um alerta hard. Muitos atacantes usam `sc stop`, `net stop`, `Stop-Service` ou `taskkill /im` — todos os quatro produzem um 7036.

### 3. Typosquatting de nome de serviço

7036 dispara para o display name mesmo quando o serviço subjacente é malicioso. Atenção para display names que parecem legítimos mas não casam com nenhum serviço Microsoft instalado: `Windows Update Service` (nome real é `Windows Update`), `Windows Defender Service` (nome real é `Windows Defender Antivirus Service`), `Microsoft Telemetry` (não existe esse serviço). Rode uma baseline de display names de um host known-good e dê diff.

### 4. Anomalias de boot

Após um reboot, o SCM sobe serviços auto-start em uma ordem razoavelmente estável. Um novo serviço auto-start aparecendo na sequência de boot 7036 — especialmente um que não estava lá no boot anterior — é um novo ponto de persistência. Cross-reference com o 7045 correspondente no ou antes do último shutdown.

## Exemplo de regra Sigma — serviço de segurança parado

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## Exemplo de KQL — sequência 7045 → 7036

O pivot de manchete. Install de persistência seguido por execução em 5 minutos no mesmo host:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

O `DisplayName` do 7036 nem sempre será literalmente igual a `ServiceName` do 7045 (um é display, outro é short) — case heuristicamente ou pré-compute um mapa para o pequeno conjunto de serviços que importam.

## Exemplo de Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapeamento ATT&CK

- **T1562.001 — Impair Defenses: Disable or Modify Tools**: 7036 `stopped` para serviços de segurança.
- **T1543.003 — Create or Modify System Process: Windows Service**: 7036 `running` combinado com 7045 para o mesmo serviço.
- **T1569.002 — System Services: Service Execution**: 7036 `running` para um `ImagePath` apontando para um binário não padrão, frequentemente como parte de movimento lateral (PsExec, execução remota baseada em SCM).
- **T1489 — Service Stop**: visando disponibilidade — parando serviços para habilitar outras ações (ransomware parando SQL Server antes de criptografar bancos).

## Falsos positivos que parecem exatamente ataques

- **Windows Update de rotina** reinicia uma dúzia de serviços em uma sequência previsível. O padrão é recorrente e rápido.
- **Atualizações de assinatura do Defender** às vezes reiniciam o próprio `WinDefend` — um `stopped` rapidamente seguido por `running` de `MsSecFlt.exe` é o padrão normal. O malicioso é *nenhum* `running` após o `stopped`.
- **Upgrades de EDR** param e reiniciam o serviço EDR. Marque as janelas de upgrade do vendor.
- **Sleep / hibernate do sistema** gera batches de registros `stopped` no sleep e `running` no wake. Combinado com eventos de `wake source` são óbvios; não alerte neles isoladamente.
- **Workloads container / Hyper-V** sobem e descem serviços constantemente.

## O que 7036 não te diz

- **Sem `AccountName`**: o registro não diz sob qual contexto de segurança o serviço está rodando. Puxe isso do 7045 correspondente ou do database do SCM.
- **Sem PID**: você não pode mapear um 7036 diretamente para um registro [4688](/pt/blog/event-id-4688-process-creation) / [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) sem correlacionar por `ImagePath` e timestamp.
- **Sem iniciador**: você não vê *quem* chamou Stop-Service. Para isso você precisa do 7035 (frequentemente desabilitado por padrão), [4688](/pt/blog/event-id-4688-process-creation) para o `net stop` / `sc stop` / `taskkill` chamador, ou [4104](/pt/blog/powershell-4104-scriptblock) para `Stop-Service`.
- **Mapeamento short-name de serviço**: o display name está em `param1`; o short name está no blob binário e deve ser decodificado. A maioria dos parsers faz isso automaticamente; se você está consultando `EventData` bruto, tem que tratar.

## Onde 7036 se encaixa em uma timeline

O combo execução lateral + defense-evasion:

1. [**4624**](/pt/blog/understanding-event-id-4624) — LogonType 3 de um host controlado pelo atacante, AuthenticationPackage Kerberos.
2. [**4688**](/pt/blog/event-id-4688-process-creation) — `services.exe` spawnando um filho para operações SCM (ou o `psexesvc.exe` do PsExec).
3. [**7045**](/pt/blog/service-creation-event-id-7045) — serviço instalado, `ImagePath` fora de caminhos de install padrão.
4. **7036** `running` — o install de fato disparou. **Essa é sua confirmação de execução.**
5. **7036** `stopped` para `WinDefend` / EDR — defense evasion antes do payload rodar.
6. [**4688**](/pt/blog/event-id-4688-process-creation) — processo de payload sob a service account.
7. **7036** `stopped` para o serviço instalador — limpeza.

7036 aparece nos passos 4, 5 e 7 — três estágios diferentes da mesma intrusão. Por si só é difícil de usar; em contexto amarra o registro de persistência (7045) à execução real e às ações de defense-evasion ao redor.
