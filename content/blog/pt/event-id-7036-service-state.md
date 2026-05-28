---
title: "Event ID 7036 explicado: mudanças de estado de serviços para triagem DFIR"
description: "O 7036 dispara sempre que um serviço inicia ou para. Combinado com o 7045 confirma se a persistência realmente correu. Por si só revela abuso de serviços, evasão de defesa e anomalias de arranque."
date: "2026-05-24"
---

O Event ID **7036**, "O serviço {service} entrou no estado {state}", dispara no [canal `System`](/pt/blog/what-is-an-evtx-file) sempre que o Service Control Manager vê uma transição de serviço. Cada início, paragem, pausa e retoma produz um. Por si só é de alto volume e fácil de descartar. Combinado com o [7045](/pt/blog/service-creation-event-id-7045) é a diferença entre "foi instalada uma backdoor" e "foi instalada uma backdoor e correu".

Para resposta a incidentes, este é o registo "executou?" mais barato que o SO lhe dá.

## Onde vive

Canal `System` no host onde o serviço correu. Sem envolvimento de DC, sem reencaminhamento por canal a preocupar-se. Está ali em `System.evtx`. Provider: `Service Control Manager`.

## O que o registo contém

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

É isto. Dois parâmetros e uma tag binária. Muito mais pequeno do que a maioria dos registos Security, e é por isso que os analistas o saltam.

- `param1`. O *display name* do serviço (não o nome curto). `Background Intelligent Transfer Service` aqui é o nome que o utilizador vê para `BITS`. Para pivotar à definição de serviço normalmente precisa do nome curto. O SCM estampa-o no `Binary` como um blob UTF-16 (`42 00 49 00 54 00 53 00` descodifica para `BITS`).
- `param2`. O novo estado: `running`, `stopped`, `paused`, `resumed` ou intermediários pendentes (`start pending`, `stop pending`). `running` e `stopped` são em que a maioria das regras se foca.

Não há `AccountName`, nem `ImagePath`, nem `ProcessId`. O 7036 diz-lhe *o que* mudou de estado, não *quem* o desencadeou. Para perceber o porquê, combine com outros registos.

## 7036, 7045, 7035, 7034: qual é qual

Quatro eventos relacionados com serviços no canal System são constantemente confundidos:

| Evento | Quando | O que lhe dá |
|---|---|---|
| **7045** | Serviço instalado | Display name, nome curto, `ImagePath`, `AccountName`, `StartType`. O ponto de persistência. |
| **7036** | Início/paragem de serviço | Apenas display name. O ponto de execução. |
| **7035** | Controlo de serviço enviado | Quem iniciou start/stop (SID), que controlo foi enviado. Raramente ligado por defeito. |
| **7034** | Serviço crashou inesperadamente | Serviço terminou sem paragem limpa. |

O padrão importa: um 7045 seguido segundos depois por um 7036 `running` para o mesmo display name é a sequência manual "instalado e correu". Um 7045 *sem* um 7036 correspondente significa que o serviço foi registado mas nunca executado: ou o atacante limpou, o instalador abortou ou o arranque foi adiado.

Um 7045 sem 7036 `running` em minutos é a sua própria anomalia. Investigue porque o install não disparou. Causas comuns: agendado para próximo reboot, definido para manual start e o atacante ainda não disparou, falha de arranque (procure erros 7034 / 7000).

### Evasão de defesa: parar serviços de segurança

O padrão mais abusado. Um atacante para `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc`, ou o serviço de um produto EDR. Cada um gera um 7036 `stopped` para o display name correspondente. Se está a ser tentada adulteração de política de auditoria ou Defender, este é um dos registos que sobrevive.

Nomes que vale a pena alertar (display names; variam por versão de Defender ou EDR):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Qualquer coisa que corresponda a `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Um 7036 `stopped` para qualquer destes, especialmente fora de uma janela de manutenção agendada, devia ser um alerta forte. Muitos atacantes usam `sc stop`, `net stop`, `Stop-Service` ou `taskkill /im`. Todos os quatro produzem um 7036.

### Typosquatting de nome de serviço

O 7036 dispara para o display name mesmo quando o serviço subjacente é malicioso. Vigie display names que parecem legítimos mas não correspondem a nenhum serviço Microsoft instalado: `Windows Update Service` (o nome real é `Windows Update`), `Windows Defender Service` (o nome real é `Windows Defender Antivirus Service`), `Microsoft Telemetry` (não existe tal serviço). Baseline display names de um host known-good e faça diff.

### Anomalias de arranque

Depois de um reboot, o SCM sobe serviços auto-start numa ordem aproximadamente estável. Um novo serviço auto-start a aparecer na sequência de 7036 do arranque, especialmente um que não estava no arranque anterior, é um novo ponto de persistência. Cruze com o 7045 correspondente no shutdown anterior ou antes.

## Sigma: serviço de segurança parado

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

## KQL: sequência 7045 para 7036

O pivot principal. Install de persistência seguido de execução em 5 minutos no mesmo host:

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

O `DisplayName` do 7036 nem sempre será literalmente igual ao `ServiceName` do 7045 (um é display, outro é curto). Faça matching heurístico ou pré-compute um mapeamento para o pequeno conjunto de serviços que importam.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapeamento ATT&CK

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` para serviços de segurança.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` emparelhado com 7045 para o mesmo serviço.
- T1569.002 System Services: Service Execution. 7036 `running` para um `ImagePath` a apontar para um binário não-padrão, muitas vezes parte de movimento lateral (PsExec, execução remota baseada em SCM, Impacket `psexec.py`).
- T1489 Service Stop. Alvo de disponibilidade (ransomware a parar SQL Server antes de encriptar bases de dados).

## Falsos positivos que parecem idênticos a ataques

- O Windows Update reinicia uma dúzia de serviços numa sequência previsível. Recorrente e rápido.
- Atualizações de assinaturas do Defender por vezes reiniciam o próprio `WinDefend`. Um `stopped` rapidamente seguido por `running` de `MsSecFlt.exe` é o padrão normal. O malicioso é *sem* `running` depois do `stopped`.
- Upgrades de EDR param e reiniciam o serviço EDR. Marque as janelas de upgrade do fornecedor.
- Sleep e hibernate do sistema geram batches de `stopped` ao adormecer e `running` ao acordar. Não alerte estes isoladamente.
- Workloads de contentores e Hyper-V sobem e descem serviços constantemente.

## O que o 7036 não lhe diz

- Sem `AccountName`. Puxe-o do 7045 correspondente ou da base de dados SCM.
- Sem PID. Não consegue mapear um 7036 diretamente para um registo [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) sem correlacionar por `ImagePath` e timestamp. A cache [prefetch](https://www.prefetchparser.com) é a corroboração secundária quando o 4688 estava off.
- Sem iniciador. Não vê quem chamou Stop-Service. Para isso precisa do 7035 (muitas vezes desativado por defeito), [4688](/pt/blog/event-id-4688-process-creation) para o `net stop` / `sc stop` / `taskkill` chamador, ou [4104](/pt/blog/powershell-4104-scriptblock) para `Stop-Service`.
- Mapeamento de nome curto do serviço. Display name está em `param1`. Nome curto está no blob binário e tem de ser descodificado. A maioria dos parsers faz isto automaticamente. Se faz query a `EventData` em bruto, tem de lidar com isto.

## Onde o 7036 encaixa numa timeline

Execução lateral mais evasão de defesa:

1. [4624](/pt/blog/understanding-event-id-4624). LogonType 3 de um host controlado pelo atacante, AuthenticationPackage Kerberos.
2. [4688](/pt/blog/event-id-4688-process-creation). `services.exe` a gerar um filho para operações SCM (ou `psexesvc.exe` do PsExec).
3. [7045](/pt/blog/service-creation-event-id-7045). Serviço instalado, `ImagePath` fora dos caminhos de instalação padrão.
4. **7036 `running`**. O install realmente disparou. Confirmação de execução.
5. **7036 `stopped`** para `WinDefend` ou EDR. Evasão de defesa antes do payload correr.
6. [4688](/pt/blog/event-id-4688-process-creation). Processo de payload sob a conta de serviço.
7. **7036 `stopped`** para o serviço instalador. Limpeza.

O 7036 aparece nos passos 4, 5 e 7. Três fases diferentes da mesma intrusão. Por si só é difícil de usar. Em contexto, liga o registo de persistência (7045) à execução real e às ações de evasão de defesa em redor.

## Leitura adicional

- [Documentação Microsoft: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
