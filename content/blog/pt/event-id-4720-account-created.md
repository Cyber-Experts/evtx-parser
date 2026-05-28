---
title: "Event ID 4720 explicado: detetar criação de contas maliciosas no AD"
description: "O 4720 dispara sempre que uma conta de utilizador é criada, local ou de domínio. Lê-lo com o 4722, 4724 e 4732 e apanha contas de persistência e movimento lateral em minutos."
date: "2026-05-24"
---

O Event ID **4720**, "Foi criada uma conta de utilizador", aterra no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que um novo utilizador é provisionado. Num domain controller dispara para cada novo utilizador de AD. Numa workstation ou member server dispara para cada nova conta local. Numa loja madura, o tráfego de 4720 é maioritariamente conduzido por RH e previsível. Essa previsibilidade é o que o torna útil. Um atacante a criar uma conta backdoor destaca-se exatamente porque o tráfego legítimo é tão regular.

Este é um dos registos de deteção de persistência mais baratos que a plataforma produz. Já fechei casos só com ele.

## Onde dispara

- Contas de domínio: o 4720 aterra no DC que tratou da criação. Recolha em todos os DCs.
- Contas locais: o 4720 aterra no host onde a conta foi criada. Apanhar isto a partir de workstations membro requer WEF ou recolha por host. Muitas lojas saltam o reencaminhamento de Security das workstations e perdem esta sinalética por completo.

Se o atacante cria uma conta *local* num servidor que já comprometeu (muitas vezes como credencial de backup), o 4720 vai estar apenas nesse servidor. Cobertura importa mais do que regras.

## O que está no registo

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

Os campos que conduzem investigações:

- `TargetUserName`. A nova conta. O nome literal é o primeiro sinal de triagem: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, semelhanças com contas legítimas (`administrator`, `administr0r`) e strings aleatórias curtas merecem todas uma análise mais próxima.
- `SubjectUserName` e `SubjectLogonId`. Quem a criou. Pivote para o [4624](/pt/blog/understanding-event-id-4624) que criou essa sessão. Um 4720 a partir de `LocalSystem` numa workstation fora de horas não é um workflow real de provisionamento.
- `UserAccountControl`. O conjunto *inicial* de flags UAC. `0x10` (no exemplo) é `NORMAL_ACCOUNT`. As flags perigosas aparecem em registos 4738 subsequentes.
- `PrimaryGroupId`. 513 (Domain Users) é normal. 512 (Domain Admins) numa conta nova é gritante e nunca devia acontecer num workflow real de provisionamento.
- `SidHistory`. Não-vazio numa conta acabada de criar é ou uma ferramenta de migração, ou, no contexto errado, um artefacto de autenticação forjada.

## O 4720 nunca vem sozinho

A criação de conta quase nunca é um evento único. A sequência mínima:

| Evento | Significado | Porque importa |
|---|---|---|
| **4720** | Conta de utilizador criada | O título. |
| **4722** | Conta de utilizador ativada | A conta está definida para permitir logon. Se o 4722 está em falta, a conta existe mas ainda não pode fazer logon. |
| **4724** | Reset de password (admin-driven) | Alguém, possivelmente não o criador, definiu ou redefiniu a password. |
| **4738** | Conta de utilizador alterada | Alterações de UAC flags, expiração, grupo, atributos. |
| **4732** | Membro adicionado a grupo local com segurança ativada | Se o grupo local é `Administrators`, isto é a concessão de privilégio. |
| **4728** | Membro adicionado a grupo global com segurança ativada | Se o grupo global é `Domain Admins` ou `Enterprise Admins`, escalada. |
| **4756** | Membro adicionado a grupo universal com segurança ativada | `Schema Admins`, `Enterprise Admins`, delegações personalizadas. |

Uma conta backdoor raramente é criada e deixada nos privilégios por defeito. A cadeia completa (4720, 4722, 4724, 4738, 4732/4728) completa-se em segundos e é o verdadeiro evento de persistência.

## Padrões de triagem

1. **Nova conta para grupo admin em minutos**. 4720 seguido de 4732 ou 4728 para um grupo privilegiado dentro de uma hora, em que o add ao grupo privilegiado não foi precedido por um ticket. Combine `TargetSid` do 4720 com `MemberSid` no 4732/4728.
2. **Criação fora de horas**. 4720 fora do horário comercial por um `SubjectUserName` que não é uma conta de serviço a correr provisionamento automatizado.
3. **Nome parecido**. `Levenshtein(TargetUserName, real_admin_name) <= 2` contra a tabela de utilizadores existente. `administrato`, `administr0r`, `helpd3sk`. Todos reais.
4. **Criado por uma conta recentemente comprometida**. 4720 em que `SubjectLogonId` remonta a um 4624 de um IP invulgar, ou a um 4624 LogonType 3 de uma workstation que o subject não usa normalmente.
5. **Criado por LocalSystem numa workstation**. 4720 com `SubjectUserSid = S-1-5-18` em qualquer coisa que não seja um domain controller ou servidor de provisionamento conhecido. Quase sempre malicioso.
6. **PrimaryGroupId == 512**. Nunca acontece em provisionamento normal. Alerta forte.

## Sigma

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

Uma variante de alta confiança combina 4720 com um 4732 ou 4728 para um grupo privilegiado dentro de 1 hora, escopado por `TargetSid`.

## KQL: 4720 mais concessão de privilégio

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

## Splunk

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

- T1136.001 Create Account: Local Account. Contas locais em workstations e servidores.
- T1136.002 Create Account: Domain Account. Criações registadas em DC.
- T1136.003 Create Account: Cloud Account. *Não* dispara o 4720. Criações na cloud vivem em logs de auditoria do Entra ID / unified audit log.
- T1098 Account Manipulation. Quando 4720 é seguido por escalada de grupo ou alterações de atributos.

## Falsos positivos que parecem ataques

- Ferramentas de migração em massa (ADMT, Quest Migration Manager) criam contas a alta velocidade com `SidHistory` definido. A forma é idêntica a um atacante rápido. Baseline as janelas de migração conhecidas.
- Pipelines de joiner em workflows de provisionamento conduzidos por RH disparam 4720 em horas previsíveis. Alertar sobre cada 4720 fora de horas vai enterrá-lo em corridas de RH que se prolongam pela meia-noite.
- Ferramentas de gestão estilo SCCM, Intune e Jamf criam contas locais para provisionamento do SO. `SubjectUserSid` é `S-1-5-18` em hosts de build conhecidos. Marque-os.
- Instaladores de serviço para alguns produtos legados criam uma conta de serviço local na primeira execução. Faça baseline ao instalador.

Deteções sólidas de 4720 combinam sempre a criação com um sinal de follow-up (add a grupo, alteração de password para um padrão fraco conhecido, login imediato a partir de um host invulgar). A criação isolada é demasiado ruidosa.

## O que o 4720 não lhe diz

O registo não inclui a password da nova conta (o Windows nunca a regista, em lado nenhum). Também não inclui explicitamente o SID do domínio alvo. Lê o domínio a partir de `TargetDomainName` ou deriva-o da porção de domínio do `TargetSid`.

Criações de contas locais em workstations membro são invisíveis para o DC. Se não está a recolher Security das workstations (a maioria das lojas não está), perde cada conta backdoor local. O Sysmon e um EDR real preenchem parte da lacuna (padrões de criação de ficheiro e alteração de registo quando o SAM local é tocado), mas o reencaminhamento de 4720 é o controlo mais barato. A snapshot da hive [registry](https://www.registryparser.com) é a corroboração quando o reencaminhamento de logs estava off.

## Onde o 4720 encaixa numa timeline

A cadeia de persistência clássica:

1. [4624](/pt/blog/understanding-event-id-4624). Logon de domínio inicial por um utilizador feito phishing.
2. Surto [4769](/pt/blog/event-id-4769-kerberoasting). Kerberoasting contra contas de serviço de domínio.
3. 4624 como uma conta de serviço comprometida num member server.
4. [4688](/pt/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (ou `New-ADUser` via PowerShell).
5. **4720**. Conta criada no DC.
6. 4724. Password definida.
7. 4722. Conta ativada.
8. 4728. Adicionada a Domain Admins.
9. [7045](/pt/blog/service-creation-event-id-7045). Serviço instalado num servidor, a correr sob a nova conta.

Instrumentar o 4720 isoladamente apanha a persistência no passo 5, antes dos passos 6 a 9 fazerem qualquer estrago. Esse é o valor.

## Leitura adicional

- [Documentação Microsoft do 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
