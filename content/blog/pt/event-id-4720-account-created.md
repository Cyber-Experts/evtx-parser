---
title: "Event ID 4720 explicado: detectando criação de conta maliciosa no AD"
description: "4720 dispara toda vez que uma conta de usuário é criada — localmente ou no AD. Leia-o com 4722/4724/4732 e você identifica contas de persistência e movimento lateral em minutos."
date: "2026-05-24"
---

O Event ID **4720** — "A user account was created" — é escrito no [canal `Security`](/pt/blog/what-is-an-evtx-file) toda vez que uma nova conta de usuário é provisionada. Em um domain controller dispara para cada novo usuário do AD; em uma estação ou member server dispara para cada nova conta local. Em uma operação madura, o tráfego de 4720 é predominantemente dirigido por RH e previsível. Essa previsibilidade é o que o torna útil: um atacante criando uma conta backdoor se destaca exatamente porque o tráfego legítimo é tão regular.

Esse é um dos registros mais baratos de detecção de persistência que a plataforma produz.

## Onde dispara

- **Contas de domínio**: 4720 cai no DC que tratou a criação. Colete em todos os DCs.
- **Contas locais**: 4720 cai no host onde a conta foi criada. Pegar isso de estações member exige WEF ou coleta por host — muitas operações pulam o encaminhamento de Security de estação e perdem totalmente este sinal.

Se o atacante criar uma conta *local* em um servidor que já comprometeu (frequentemente como credencial de backup), o 4720 estará só nesse servidor. Cobertura importa.

## O que o registro contém

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

Os campos que dirigem investigações:

- **`TargetUserName`** — a nova conta. O nome literal é o primeiro sinal de triagem: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, lookalikes de contas legítimas (`administrator`, `administr0r`) e strings curtas aleatórias todos merecem uma olhada.
- **`SubjectUserName` / `SubjectLogonId`** — *quem* a criou. Pivote para o [4624](/pt/blog/understanding-event-id-4624) que criou essa sessão. Um 4720 de `LocalSystem` em uma estação fora do horário comercial não é um workflow real de provisionamento.
- **`UserAccountControl`** — o conjunto *inicial* de flags UAC. `0x10` (o exemplo) é `NORMAL_ACCOUNT`; as flags perigosas aparecem em registros 4738 (conta alterada) subsequentes. O bitmap UAC completo está em MS-SAMR.
- **`PrimaryGroupId`** — 513 (Domain Users) é normal; 512 (Domain Admins) em uma nova conta é uma anomalia estridente que nunca deveria acontecer em um workflow real de provisionamento.
- **`SidHistory`** — `SidHistory` não vazio em uma conta *recém-criada* é forte sinal de uma ferramenta de migração — ou, no contexto errado, um artefato forjado de autenticação.

## Os registros com os quais 4720 não vem sozinho

Criação de conta quase nunca é um único evento. A sequência mínima:

| Evento | Significado | Por que importa |
|---|---|---|
| **4720** | Conta de usuário criada | A manchete. |
| **4722** | Conta de usuário habilitada | A conta foi setada para permitir logon. Se 4722 estiver ausente, a conta existe mas ainda não pode fazer logon. |
| **4724** | Senha redefinida (admin-driven) | Alguém — possivelmente não o criador — definiu ou redefiniu a senha. |
| **4738** | Conta de usuário alterada | Flags UAC, expiração, grupo, mudanças de atributo. |
| **4732** | Membro adicionado a um grupo local security-enabled | Se o grupo local for `Administrators`, esse é o privilege grant. |
| **4728** | Membro adicionado a um grupo global security-enabled | Se o grupo global for `Domain Admins` ou `Enterprise Admins`, escalada. |
| **4756** | Membro adicionado a um grupo universal security-enabled | `Schema Admins`, `Enterprise Admins`, delegações customizadas. |

Uma conta backdoor raramente é criada e deixada com privilégio padrão. A cadeia completa — `4720 → 4722 → 4724 → 4738 (flags UAC) → 4732/4728 (add em grupo)` — se completa em segundos e é o evento real de persistência.

## Padrões de triagem

1. **Nova conta → grupo admin em minutos**: 4720 seguido por 4732/4728 para um grupo privilegiado em uma hora, onde o add ao grupo privilegiado *não* foi precedido por um ticket no sistema de change-management. Combine o `TargetSid` do 4720 com `MemberSid` em 4732/4728.
2. **Criação fora de horário**: 4720 fora do horário comercial por um `SubjectUserName` que não é uma service account fazendo provisionamento automatizado.
3. **Nome lookalike**: `Levenshtein(TargetUserName, real_admin_name) <= 2` contra a tabela de usuários existente. `administrato`, `administr0r`, `helpd3sk` — todos são casos reais.
4. **Criada por uma conta recém-comprometida**: 4720 onde `SubjectLogonId` rastreia de volta a um 4624 de um IP incomum, ou um 4624 LogonType 3 de uma estação que o sujeito normalmente não usa.
5. **Criada por `LocalSystem` em uma estação**: 4720 com `SubjectUserSid = S-1-5-18` em qualquer coisa que não seja um domain controller ou servidor de provisionamento conhecido. Quase sempre malicioso.
6. **`PrimaryGroupId == 512`**: nunca acontece em provisionamento normal. Alerta hard.

## Exemplo de regra Sigma

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

Uma variante de alta confiança: combine 4720 com um 4732/4728 para um grupo privilegiado em 1 hora, escopado por `TargetSid`.

## Exemplo de KQL — 4720 + privilege grant

KQL (Sentinel) — o pivot "nova conta → grupo admin":

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Exemplo de Splunk

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## Mapeamento ATT&CK

- **T1136.001 — Create Account: Local Account** para contas locais de estação/servidor.
- **T1136.002 — Create Account: Domain Account** para criações registradas em DC.
- **T1136.003 — Create Account: Cloud Account** — *não* dispara 4720 (criações de cloud account estão nos audit logs do Azure AD / unified audit log, não em Windows Security).
- **T1098 — Account Manipulation** quando 4720 é seguido por escalada de grupo ou mudanças de atributo.

## Falsos positivos que parecem exatamente ataques

- **Ferramentas de migração em massa** (ADMT, Quest Migration Manager) criam contas em velocidade com `SidHistory` setado. A forma do tráfego é idêntica a um atacante rápido; baseline as janelas de migração conhecidas.
- **Pipelines de joiner** em workflows de provisionamento dirigidos por RH disparam 4720 em horários previsíveis. Se você alerta em todo 4720 fora de horário, vai se enterrar em rodadas de sistema de RH que avançam pela meia-noite.
- **Ferramentas de gestão SCCM / Intune / estilo Jamf** criam contas locais para provisionamento de SO. O `SubjectUserSid` será `S-1-5-18` (LocalSystem) em hosts de build conhecidos; marque esses hosts.
- **Instaladores de serviço** para alguns produtos legados criam uma service account local na primeira execução. Baseline o instalador.

Detecções sólidas de 4720 sempre combinam a criação com um sinal de follow-up (add a grupo, mudança de senha para um padrão fraco conhecido, login imediato de um host incomum). A criação standalone é barulhenta demais.

## O que 4720 não te diz

O registro não inclui a *senha* da nova conta (o Windows nunca registra isso, em lugar nenhum). Também não inclui o SID do *domínio alvo* explicitamente; você lê o domínio de `TargetDomainName` ou deriva da porção de domínio do `TargetSid`.

Criações de conta local em estações member são invisíveis ao DC. Se você não está coletando Security de estações (a maioria das operações não está), você perderá toda conta backdoor local. Sysmon e um EDR real preenchem parte do gap (padrões de file create / mudança de registry quando o SAM local é tocado), mas o encaminhamento de 4720 é o jeito mais barato.

## Onde 4720 se encaixa em uma timeline

A cadeia escolar de persistência:

1. [**4624**](/pt/blog/understanding-event-id-4624) — logon de domínio inicial por um usuário phisheado.
2. [**4769**](/pt/blog/event-id-4769-kerberoasting) burst — kerberoasting contra service accounts de domínio.
3. **4624** como uma service account comprometida em um member server.
4. [**4688**](/pt/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain` (ou o mesmo via PowerShell `New-ADUser`).
5. **4720** — conta criada no DC.
6. **4724** — senha definida.
7. **4722** — conta habilitada.
8. **4728** — adicionada a Domain Admins.
9. [**7045**](/pt/blog/service-creation-event-id-7045) — serviço instalado em um servidor, rodando sob a nova conta.

Se você instrumentar 4720 sozinho, pega a persistência no passo 5 — antes dos passos 6-9 causarem dano. Esse é o valor.
