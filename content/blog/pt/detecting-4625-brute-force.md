---
title: "Event ID 4625 explicado: detectando brute force, sprays e enumeração"
description: "4625 é o registro de falha de logon. Lido corretamente, você identifica password sprays, credential stuffing e abuso de Kerberos antes que tenham sucesso."
date: "2026-05-17"
---

O Event ID 4625 — «Uma conta falhou ao fazer logon» — dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que uma tentativa de autenticação é rejeitada. É o registro mais útil para detectar atividade de ataque a credenciais, mas só se você ler os campos certos.

## Os campos que realmente importam

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

A combinação de `Status` e `SubStatus` diz *por que* o logon falhou:

- `0xc0000064` — conta não existe (enumeração de usernames).
- `0xc000006a` — senha errada (o clássico).
- `0xc0000234` — conta bloqueada.
- `0xc0000072` — conta desabilitada.
- `0xc0000071` — senha expirada.
- `0xc0000133` — clock skew em um ticket Kerberos (comum durante AS-REP roasting).
- `0xc000018b` — SID errado — a estação não está no domínio que ela acha.

Uma rajada de `0xc0000064` contra usernames válidos e inválidos é reconnaissance. Uma rajada de `0xc000006a` contra uma conta é brute force. Uma rajada de `0xc000006a` contra muitas contas com a *mesma senha* é um password spray.

## Os padrões

As queries mais simples de triagem:

1. **Detecção de spray**: agrupe registros 4625 por `IpAddress` (ou `WorkstationName` se o IP não estiver registrado), conte `TargetUserName` distintos em 10 minutos. >5 contas por origem nessa janela é suspeito em quase qualquer lugar.
2. **Brute force**: agrupe por `TargetUserName`, conte falhas por minuto. >10 por minuto contra uma conta é normalmente um bot.
3. **Causa raiz de lockout**: combine 4740 (conta bloqueada) com os 4625s precedentes — o campo `WorkstationName` mostrará qual dispositivo disparou o lockout, o que é crítico porque frequentemente é um servidor ingressado no domínio com uma credencial armazenada desatualizada, não um atacante.

## O "depois" importa tanto quanto o "antes"

Uma rajada de 4625 seguida por um [4624](/pt/blog/understanding-event-id-4624) do mesmo `IpAddress` é o caso acionável — o atacante encontrou uma credencial funcional. O parser nesta página permite filtrar a tabela por um IP de origem e observar as transições de level e event-ID ao longo do tempo na timeline. O padrão rajada-depois-pico é inconfundível.

## Exemplo de regra Sigma — password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
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

## Exemplo de KQL — brute force contra uma conta

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Exemplo de Splunk — enumeração antes do brute

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

O sinal é a *progressão* — enumeração para encontrar usernames válidos, depois brute force contra eles.

## Mapeamento ATT&CK

- **T1110.001 — Brute Force: Password Guessing**: uma conta, muitas falhas `0xC000006A`.
- **T1110.003 — Brute Force: Password Spraying**: muitas contas, poucas falhas por conta, uma origem.
- **T1110.004 — Brute Force: Credential Stuffing**: muitas contas, uma origem, frequentemente `0xC0000064` (conta não existe) para misses de listas vazadas intercaladas com hits `0xC000006A`.
- **T1078 — Valid Accounts**: 4625 seguido de sucesso de [4624](/pt/blog/understanding-event-id-4624) da mesma origem = comprometimento.
- **T1556 — Modify Authentication Process**: `LogonProcessName` anômalo (qualquer coisa diferente de `User32`, `NtLmSsp`, `Kerberos`, `Advapi` ou `Schannel`) sugere tampering de autenticação.

## Falsos positivos que parecem ataques

- **Credenciais armazenadas envelhecidas** após mudança de senha. Os mapeamentos de drive do usuário, tarefas agendadas ou configurações de service account continuam tentando a senha antiga. O padrão: um `TargetUserName`, um `IpAddress` (às vezes um `WorkstationName`), cadência constante de `0xC000006A`. Cace o host com a credencial desatualizada e conserte.
- **Automação mal configurada**: um script com senha errada tentando em loop. Mesma forma do brute force; fale com o dono antes de alertar.
- **Scanners de vulnerabilidade** durante scans autenticados produzem tráfego denso de 4625. Marque os IPs dos scanners.
- **Configuração errada de política de lockout**: procedimentos de helpdesk que desbloqueiam de forma muito agressiva podem produzir ciclos repetidos 4625 → 4740 → 4624.

## O que você não vê no 4625

Falhas de NTLMv2 e Kerberos vindas de um domain controller nem sempre carregam um `IpAddress` útil — o campo pode estar vazio ou `-`. Para isso você precisa dos eventos correspondentes do DC ([4768](/pt/blog/event-id-4768-kerberos-tgt)/4771 para falhas de pré-autenticação Kerberos) ou dados em nível de rede. Não conclua "sem IP de origem, sem investigação" — pivote para o canal do DC.

Os campos `LogonProcessName` e `AuthenticationPackageName` dizem qual stack de autenticação tratou a tentativa. Os mais úteis são `NtLmSsp` (NTLM), `Kerberos` e `Negotiate` (que escolhe um dos dois). `User32` é console local; `Schannel` é baseado em TLS.
