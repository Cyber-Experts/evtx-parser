---
title: "Event ID 4625 explicado: deteção de brute force, sprays e enumeração"
description: "O 4625 é o registo de logon falhado. Lê-lo bem permite identificar password sprays, credential stuffing e abuso de Kerberos antes que se tornem um sucesso."
date: "2026-05-17"
---

O Event ID 4625, "An account failed to log on", dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que uma tentativa de autenticação é rejeitada. É o registo mais útil para apanhar ataques de credenciais em andamento. Também é o registo que os analistas mais frequentemente leem mal, porque a mensagem principal é genérica e a resposta vive dois campos mais fundo.

## Os campos que decidem a chamada

Um registo típico:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` e `SubStatus` em conjunto dizem-lhe porque é que o logon falhou. O par que verdadeiramente interessa é o `SubStatus`. Os códigos que vale a pena memorizar:

- `0xC0000064`: conta não existe. Enumeração de nomes de utilizador.
- `0xC000006A`: password errada. O clássico.
- `0xC0000234`: conta bloqueada.
- `0xC0000072`: conta desativada.
- `0xC0000071`: password expirada.
- `0xC0000133`: clock skew Kerberos. Comum em tentativas de AS-REP roasting em que o atacante forjou um relógio.
- `0xC000018B`: SID errado, a workstation pensa que está num domínio em que não está. Raro e interessante.

Um surto de `0xC0000064` em nomes válidos e inválidos misturados é reconhecimento. Um surto de `0xC000006A` contra uma conta é brute force. Um surto de `0xC000006A` contra muitas contas usando a *mesma* password é spray. Mesmo Event ID, três incidentes diferentes.

## As queries de triagem que valem o seu lugar

1. Deteção de spray. Agrupe 4625 por `IpAddress` (ou `WorkstationName` se o campo IP estiver vazio), conte `TargetUserName` distintos em 10 minutos. Mais de cinco contas por origem nessa janela é suspeito quase em qualquer lado.
2. Brute force. Agrupe por `TargetUserName`, conte falhas por minuto. Mais de dez por minuto contra uma conta é quase sempre automatizado.
3. Causa raiz de bloqueio. Combine o 4740 (conta bloqueada) com os 4625 que o precedem. O campo `WorkstationName` diz-lhe que dispositivo despoletou o bloqueio. A maior parte das vezes é um servidor inscrito no domínio com uma credencial em cache stale, não um atacante. A triagem importa porque o helpdesk trata os dois da mesma forma e o SOC tem de escolher qual escalar.

## O "depois" decide a resposta

Um surto de 4625 seguido de um [4624](/pt/blog/understanding-event-id-4624) a partir do mesmo `IpAddress` é o caso acionável. O atacante encontrou uma credencial que funciona. A progressão na timeline é inconfundível: falhas densas, silêncio súbito, sucesso único.

## Sigma: password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL: brute force contra uma conta

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: enumeração a transitar para brute

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

O sinal é a *progressão*: primeiro enumeração para encontrar nomes válidos, depois tentativas de password dirigidas. Um operador real com uma lista de utilizadores fresca produz ambas as formas em minutos.

## Mapeamento ATT&CK

- T1110.001 Brute Force: Password Guessing. Uma conta, muitas falhas `0xC000006A`.
- T1110.003 Brute Force: Password Spraying. Muitas contas, uma origem, poucas falhas em cada.
- T1110.004 Credential Stuffing. Muitas contas, uma origem, `0xC0000064` (conta não existe, falha de lista vazada) e `0xC000006A` (acerto) misturados.
- T1078 Valid Accounts. Surto de 4625 seguido de sucesso [4624](/pt/blog/understanding-event-id-4624) da mesma origem. Comprometimento.
- T1556 Modify Authentication Process. Um `LogonProcessName` anómalo (qualquer coisa diferente de `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) sugere adulteração.

## Falsos positivos que vestem o disfarce

- Credenciais guardadas que ficam stale depois de uma mudança de password. As drives mapeadas, tarefas agendadas ou configs de serviços do utilizador voltam a tentar a password antiga. A forma é um `TargetUserName`, um `IpAddress`, cadência estável de `0xC000006A`. Encontre o host com a credencial stale e corrija antes de alertar.
- Automação mal configurada. Um script com a password errada a fazer retry em loop. Mesma forma que brute force. Fale primeiro com o owner.
- Vulnerability scanners durante varreduras autenticadas produzem tráfego denso de 4625. Marque IPs de scanner.
- Rotatividade de política de bloqueio. Procedimentos de helpdesk que desbloqueiam agressivamente criam ciclos repetidos de 4625 para 4740 para 4624. Incómodo. Não malicioso.

## O que o 4625 esconde

Falhas Kerberos e NTLMv2 a passar por um DC nem sempre transportam um `IpAddress` útil. O campo pode estar vazio ou ser `-`. Para esses, pivote para os registos do DC: [4768](/pt/blog/event-id-4768-kerberos-tgt) e 4771 para falhas de pré-autenticação Kerberos. "Sem IP de origem, sem investigação" é o instinto errado. Olhe para o log do DC.

Os campos `LogonProcessName` e `AuthenticationPackageName` dizem-lhe que stack de autenticação tratou da tentativa. Valores úteis: `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (escolhe um dos dois), `User32` (consola local), `Schannel` (TLS). Qualquer outra coisa, olhe melhor.

## Leitura adicional

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
