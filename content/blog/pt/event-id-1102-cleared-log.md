---
title: "Event ID 1102 explicado: log de auditoria de segurança limpo (e o que sobrevive)"
description: "O 1102 é o único evento que não consegue suprimir sem deixar mais evidência atrás de si. Eis o que diz, o que sobrevive à limpeza e onde procurar quando o vir."
date: "2026-05-17"
---

O Event ID **1102** é o que o Windows escreve no [canal `Security`](/pt/blog/what-is-an-evtx-file) quando alguém limpa o log de auditoria. É, por desenho, um dos registos mais difíceis de um atacante suprimir. Suprimi-lo de forma limpa exige ou substituir o binário do serviço EventLog antes deste arrancar, ou aceitar que o ato de limpar deixa o seu próprio 1102. A maioria dos operadores escolhe a segunda opção, na esperança de que ninguém esteja a prestar atenção.

Se vir um 1102, alguém com privilégio suficiente apagou deliberadamente o trilho de auditoria. Isto essencialmente nunca é uma ação rotineira de administração e, quando é, deve estar ticketada. Trate cada 1102 fora de uma janela de manutenção aprovada como um incidente até prova em contrário.

## O que está no registo

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

Note o bloco `UserData` em vez do habitual `EventData`. O 1102 usa um esquema de user-data estruturado, o que tropeça parsers ingénuos que só olham para `EventData`. Os campos dizem-lhe quem limpou o log sob que sessão de logon. Pivote em `SubjectLogonId` para o [4624](/pt/blog/understanding-event-id-4624) correspondente e tem o IP de origem, o tipo de logon e a credencial que produziu a sessão privilegiada.

## O que viaja ao lado

Uma limpeza de log raramente é a única ação anti-forense da cadeia. Os registos que tendem a disparar perto dele, em ordem cronológica aproximada:

- **104** no canal `System`. Mesmo ato que o 1102 mas registado pelo SCM para canais que não Security. Se o 104 está presente e o 1102 está em falta, o atacante limpou apenas Security e esqueceu-se do System.
- **4719**, "a política de auditoria do sistema foi alterada". Por vezes o atacante reduz a cobertura de auditoria *antes* de limpar, para deixar menos registos da próxima vez.
- **4616**, "a hora do sistema foi alterada". Timestomping pré-limpeza torna a reconstrução da timeline mais difícil.
- Uma lacuna nos 4624s na hora ou duas antes do 1102. O atacante pode ter usado um canal lateral não registado para entrar.

## O que sobrevive à limpeza

Limpar o log de eventos em memória não toca em:

- Outros canais. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canais de eventos reencaminhados. Nenhum destes é limpo por uma limpeza do Security.
- Eventos reencaminhados. Se o Windows Event Forwarding está a enviar Security para um coletor, os registos limpos já estão noutro host. Os RecordIDs e timestamps originais são preservados.
- O próprio ficheiro em disco. Um `Security.evtx` limpo é substituído por um ficheiro novo. Os clusters do ficheiro anterior frequentemente persistem em espaço não alocado. Os registos EVTX [recuperam-se limpamente](/pt/blog/carve-deleted-evtx-records) a partir desses clusters.
- Entradas do [USN journal](https://www.usnparser.com) para a substituição do ficheiro. Mesmo o ato de limpar deixa artefactos ao nível do filesystem.
- A entrada [MFT](https://www.mftparser.com) para o novo ficheiro, que carrega um timestamp de criação que deve coincidir com o 1102 ao segundo.

Uma "limpeza bem-sucedida" de log raramente é tão limpa como o atacante espera.

## Sigma: log limpo

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
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

## KQL: limpeza correlacionada com sessão privilegiada

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

Cada 1102 remonta a um [4672](/pt/blog/event-id-4672-special-privileges) a conceder `SeSecurityPrivilege`, que remonta a um [4624](/pt/blog/understanding-event-id-4624). O join completa o quadro.

## Splunk: a cadeia de adulteração

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Um LogonId que tocou na política de auditoria (4719) ou na hora do sistema (4616) e depois limpou um log (1102/104) é a cadeia de adulteração.

## Mapeamento ATT&CK

- T1070.001 Indicator Removal: Clear Windows Event Logs. O título. O 1102 *é* o indicador primário.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 antes de 1102 mapeia aqui.
- T1070.006 Indicator Removal: Timestomp. Combinado com 4616 na mesma cadeia.
- T1078.003 Valid Accounts: Local Accounts. 1102 por um Administrador local que não devia estar logged on naquele momento.

## Falsos positivos, raros mas reais

- Workflows de migração ou descomissionamento. Técnicos a limpar logs num host a ser descomissionado. Deve estar sempre ticketado.
- Laboratórios forenses a correr ciclos de clear-and-reproduce durante desenvolvimento de deteção.
- Algumas ferramentas legadas limpam o log para "reset de baselines". Quase sempre um erro processual, mas real.

Não há razão segura para um 1102 em operação normal. Mesmo os legítimos devem ser investigados e documentados a posteriori.

## Quando encontra um no bundle

Quando carrega um [ficheiro .evtx numa ferramenta forense](/pt/blog/how-to-open-an-evtx-file), as duas primeiras pesquisas que vale a pena correr são `EventID:1102` e `EventID:104`. Se alguma estiver presente, o log que tem em mãos tem lacunas conhecidas. Qualquer timeline construída a partir dele está incompleta. Anote-o de forma bem visível no relatório. Depois vá ver o que sobreviveu: o [registry](https://www.registryparser.com), [USN journal](https://www.usnparser.com), [MFT](https://www.mftparser.com), [prefetch](https://www.prefetchparser.com) e [AmCache](https://www.amcacheparser.com). Juntos reconstroem a maior parte do que o 1102 tentou apagar.

Ferramentas como o `Invoke-Phant0m` ignoram o 1102 por completo, suspendendo as threads do serviço de eventos em vez de limpar. Se vir um silêncio de várias horas no Security sem 1102 e sem shutdown do sistema, é a outra forma do mesmo problema.

## Leitura adicional

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Documentação Microsoft do 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
