---
title: "Event ID 1102 explicado: log de auditoria de segurança limpo (e o que sobrevive)"
description: "1102 é o único evento que você não consegue suprimir sem deixar mais evidência. Eis o que ele te diz e o que sobrevive à limpeza."
date: "2026-05-17"
---

O Event ID **1102** é o registro que o Windows escreve no [canal `Security`](/pt/blog/what-is-an-evtx-file) quando o log de auditoria é limpo. Ele é — por design — um dos registros mais difíceis para um atacante suprimir, porque suprimi-lo exige ou substituir com sucesso o serviço EventLog antes que ele inicialize, ou aceitar que o ato de limpar deixa um 1102 próprio.

Para os defensores isso significa: se você vê 1102, alguém com privilégio suficiente deliberadamente apagou a trilha de auditoria. Isso quase nunca é uma ação normal de administrador.

## O que tem no registro

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Note o bloco `UserData` em vez do usual `EventData` — 1102 é um dos registros que usa um esquema estruturado de user-data. Os campos te dizem *quem* limpou o log sob qual sessão de logon. Pivote em `SubjectLogonId` para encontrar o [4624](/pt/blog/understanding-event-id-4624) correspondente e você terá o IP de origem e o tipo de logon que produziu a sessão privilegiada.

## O que também dispara quando 1102 dispara

Uma limpeza de log raramente é a *única* ação anti-forense. Acompanhantes comuns, em ordem cronológica aproximada:

- **104** no canal `System` — mesmo ato, registrado pelo SCM. Se 104 está presente mas 1102 está ausente, o atacante só limpou o Security log e esqueceu do System.
- **4719** — "System audit policy was changed". Às vezes um atacante reduz cobertura de auditoria *antes* de limpar, para deixar menos registros na próxima rodada.
- **4616** — "The system time was changed". Skew de tempo pré-limpeza torna a reconstrução de timeline mais difícil.
- **Uma lacuna em 4624s** por uma ou duas horas antes do 1102 — o atacante pode ter usado um canal lateral não registrado.

## O que sobrevive a uma limpeza

Limpar o event log em memória não toca:

- **Outros canais**: `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canais de eventos encaminhados — nenhum desses é limpo por um wipe do Security.
- **Eventos encaminhados**: se Windows Event Forwarding (WEF) está configurado para um coletor central, os registros limpos já estão em outro host.
- **O próprio arquivo em disco**: um `Security.evtx` limpo é substituído por um novo arquivo; os clusters do arquivo anterior *deletado* frequentemente persistem em espaço não alocado e podem ser recuperados com ferramentas NTFS.
- **Entradas do USN journal** para a substituição do arquivo: mesmo a operação de limpeza deixa artefatos em nível de filesystem.

Uma limpeza de log "bem-sucedida" raramente é tão limpa quanto o atacante espera.

## Exemplo de regra Sigma — log limpo

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

Se você vir 1102 fora de uma janela de manutenção aprovada, trate como incidente — ponto final.

## Exemplo de KQL — correlação limpeza de log + sessão privilegiada

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Todo 1102 rastreia de volta para um [4672](/pt/blog/event-id-4672-special-privileges) concedendo `SeSecurityPrivilege` — que rastreia de volta para um [4624](/pt/blog/understanding-event-id-4624). O join completa o quadro.

## Exemplo de Splunk — cadeia anti-forense de acompanhantes

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Um `LogonId` que tocou política de auditoria (4719) ou tempo do sistema (4616) e depois limpou um log (1102/104) é a cadeia de tampering.

## Mapeamento ATT&CK

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**: a técnica principal. 1102 *é* o indicador primário dessa técnica.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: 4719 (política de auditoria alterada) precedendo 1102 mapeia aqui.
- **T1070.006 — Indicator Removal: Timestomp**: combinado com 4616 (tempo do sistema alterado) na mesma cadeia.
- **T1078.003 — Valid Accounts: Local Accounts**: 1102 por um Administrator local que não deveria ter feito logon naquele horário.

## Falsos positivos — raros, mas reais

- **Workflows de migração / decom**: técnicos limpando o log em um host sendo decomissionado. Deve sempre ser ticketado.
- **Labs forenses / de teste**: workflows de clear-and-reproduce durante desenvolvimento de detecção.
- **Algumas ferramentas legadas** limpam o log para resetar baselines — quase sempre um erro procedural, mas real.

O sinal é tão diretamente anti-forense que mesmo 1102s legítimos devem ser investigados e documentados após o fato. Não há razão "segura" para um 1102 em operações normais.

## Por que isso importa para parsing

Quando você [carrega um arquivo .evtx em uma ferramenta forense](/pt/blog/how-to-open-an-evtx-file), a *primeira* busca que vale rodar é `EventID:1102` e `EventID:104`. Se algum estiver presente, o log que você tem possui lacunas conhecidas e qualquer timeline que você construa a partir dele é incompleta. Note isso claramente no relatório.
