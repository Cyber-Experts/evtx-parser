---
title: "Event ID 4769 explicado: service tickets Kerberos e kerberoasting"
description: "4769 é o registro do DC de cada requisição de service ticket. Leia-o pelo encryption type e você identifica kerberoasting; leia-o com 4768 e você identifica pass-the-ticket."
date: "2026-05-24"
---

O Event ID **4769** — "A Kerberos service ticket was requested" — dispara em todo Domain Controller toda vez que qualquer conta requisita um ticket TGS (Ticket Granting Service) para um serviço. Toda conexão SMB, todo login SQL, todo hit de SSO web produz um desses no DC que tratou a requisição. É o registro de maior volume no [canal Security](/pt/blog/what-is-an-evtx-file) em um DC ocupado — e o único lugar onde kerberoasting aparece de forma confiável antes das credenciais serem crackeadas offline.

Se você só consegue instrumentar três registros Security dos seus domain controllers, este é um deles.

## Onde vive

`4769` é escrito no canal `Security` do **Domain Controller emissor** — não no cliente e não no serviço alvo. Para ver todos os registros 4769 de um domínio, você tem que coletar de todo DC. O target `EventLogs` do KAPE em um DC, ou encaminhar `Security` via WEF para um coletor, ambos funcionam; a rota WEF é a que a maioria das operações maduras usa.

## O que o registro contém

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

Os campos que dirigem triagem:

- **`TargetUserName`** — o *requisitante* (a conta de usuário, em forma `user@DOMAIN`).
- **`ServiceName`** — o SPN sendo requisitado. Uma conta de usuário aqui (em vez de `host/...` ou uma classe de serviço) é suspeito.
- **`TicketEncryptionType`** — o valor que decide se este registro importa. Domínios modernos rodam `0x12` (AES-256-CTS-HMAC-SHA1-96) ou `0x11` (AES-128). **`0x17` é RC4-HMAC** — legado, fraco e o *único* encryption type que o modo `kerberoast` de Mimikatz/Rubeus requisita. Um 4769 para um ticket de service account com `0x17` é um fingerprint escolar de kerberoasting.
- **`Status`** — `0x0` é sucesso; qualquer outra coisa significa negado (códigos de status documentados em `[MS-KILE]`).
- **`IpAddress`** — o host requisitante. Combine com [4624](/pt/blog/understanding-event-id-4624) nesse host para ver o logon que produziu a sessão.

## TicketEncryptionType — o campo que importa

A tabela completa, abreviada:

| Valor | Algoritmo | Status |
|---|---|---|
| 0x01 | DES-CBC-CRC | Desabilitado por padrão desde Win7 |
| 0x03 | DES-CBC-MD5 | Desabilitado por padrão desde Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (padrão para a maioria das contas) |
| **0x17** | **RC4-HMAC-MD5** | **Legado. Requerido para kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 export-grade, extremamente raro |

Se o domínio foi baseliened e `msDS-SupportedEncryptionTypes` setado para AES-only em service accounts, `0x17` não deveria aparecer para essas contas. Atacantes requisitam `0x17` explicitamente porque crackear service tickets criptografados com RC4 é computacionalmente barato; AES não é. A ferramenta de cracking precisa do hash RC4, então a requisição *tem* que ser 0x17.

Esse é o campo de maior sinal no registro.

## O padrão de kerberoasting

Kerberoasting (MITRE T1558.003) funciona assim:

1. Atacante autentica com qualquer conta de usuário de domínio (nenhum direito admin necessário).
2. Atacante enumera SPNs registrados a contas de usuário (não contas de computador), tipicamente via LDAP `(servicePrincipalName=*)` filtrado para objetos de usuário.
3. Atacante requisita um TGS para cada SPN com `etype=23` (RC4) via o protocolo Kerberos padrão. **Esse é o 4769 que você está procurando.**
4. O DC alegremente emite o ticket, criptografado com o hash NTLM da *service account*.
5. Atacante puxa o blob criptografado da memória (ou do fio) e cracka offline com Hashcat (`-m 13100`).

O fingerprint do 4769:

- `ServiceName` é `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` ou qualquer SPN apontando para uma conta de *usuário* (não `host/...` ou `cifs/...` que são contas de computador).
- `TicketEncryptionType` é `0x17`.
- Uma rajada dessas requisições em uma janela curta, da mesma origem, para muitos SPNs, é o sinal definitivo.

Um segundo padrão relacionado — **AS-REP roasting** (T1558.004) — usa [4768](/pt/blog/event-id-4768-kerberos-tgt) em vez (a requisição de TGT), visando contas com `DONT_REQUIRE_PREAUTH` setado. Registro diferente, mesma família de ataques.

## Pass-the-ticket / golden / silver tickets

4769 também revela forjamento de ticket, mas o sinal é mais sutil.

- Um 4769 *sem* um 4768 precedente (requisição de TGT) para o mesmo `LogonGuid` do mesmo host em uma janela razoável — suspeita de **golden ticket**. O atacante apresentou um TGT forjado e foi direto para requisições de TGS sem nunca pedir um TGT real.
- Um 4769 *e* a autenticação de serviço resultante no alvo *sem* um 4769 visível em qualquer DC — suspeita de **silver ticket**. O atacante forjou o próprio TGS; o DC nunca foi consultado.
- Mismatch de `LogonGuid` entre 4624 no serviço alvo e o 4769 supostamente emitindo o ticket — ticket forjado.

Esses são padrões de detecção-por-ausência, o que significa que exigem cobertura completa de log em todos os DCs e nos serviços alvo. Lacunas na cobertura WEF produzem falsos positivos idênticos; caracterize sua coleta antes de alertar.

## Workflow de triagem

1. Filtre todos os 4769 no corpus de DCs por `TicketEncryptionType == 0x17`.
2. Agrupe por `IpAddress` e por `TargetUserName` em janelas de 30 minutos. Conte `ServiceName` distintos por origem.
3. >3 SPNs distintos requisitados como 0x17 de uma origem em 30 minutos é kerberoasting em quase qualquer lugar.
4. Pivote o IP de origem para seu [4624](/pt/blog/understanding-event-id-4624) no host de origem — encontre a credencial que iniciou o ataque.
5. Pivote os SPNs requisitados para as service accounts que os possuem. Rotacione essas senhas. Reset hashes crackeados em horas, não dias.

## Exemplo de regra Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

A cláusula `filter_machine` exclui SPNs de conta de computador (que sempre terminam em `$`); kerberoasting só visa SPNs de conta de usuário.

## Exemplo de KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapeamento ATT&CK

O corpus de 4769 cobre:

- **T1558.003 — Kerberoasting**: o caso de uso de manchete.
- **T1558.001 — Golden Ticket**: 4769 sem 4768 do mesmo `LogonGuid`.
- **T1558.002 — Silver Ticket**: 4769 ausente para uma autenticação de serviço observada no alvo.
- **T1078 — Valid Accounts**: 4769 de um IP inesperado para uma service account conhecida.
- **T1550.003 — Pass the Ticket**: 4769 seguido por [4624](/pt/blog/understanding-event-id-4624) LogonType 3 com `LogonProcessName: Kerberos`.

## Falsos positivos que você verá

- **Aplicações legadas** (alguns conectores SQL Server antigos, algumas apps Java/JBoss) requisitam explicitamente RC4. Aparecem como tráfego 0x17 constante e diurno de um pequeno conjunto de hosts estáveis. Baseline e exclua.
- **Domínios pré-AES** durante uma transição de hardening Kerberos emitirão 0x17 amplamente até `msDS-SupportedEncryptionTypes` ser setado em toda conta. Irritante; não malicioso.
- **Scanners de vulnerabilidade** (Tenable, Qualys, scripts de enumeração BloodHound) replicam tráfego de kerberoasting. Marque hosts de scanner.
- **Ferramentas de migração de conta** durante movimentações cross-forest podem requisitar combinações incomuns de ticket.

O sinal é o padrão de *rajada*, não o registro individual. 0x17 constante de um host é configuração; 0x17 em rajada para muitos SPNs de um host em minutos é o ataque.

## O que 4769 não te diz

O registro não inclui o ticket criptografado em si — o cracking acontece no que o atacante exfiltrou, não no fio do DC. Você não pode, somente a partir do 4769, distinguir "ticket foi emitido e nunca usado" de "ticket foi crackeado, credenciais reutilizadas". Para a segunda metade da cadeia você precisa do [4624](/pt/blog/understanding-event-id-4624) resultante no serviço alvo (LogonType 3, AuthenticationPackage Kerberos), e idealmente [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) mostrando o que rodou depois que a credencial foi reutilizada. Trate 4769 como o canário, não o alarme.

## Onde 4769 se encaixa em uma timeline

Cadeia clássica de pós-exploração com kerberoasting:

1. [**4624**](/pt/blog/understanding-event-id-4624) em uma estação — acesso inicial via credenciais phisheadas de usuário.
2. **4769** ×N daquele IP de estação para um DC, todos `etype=0x17`, todos visando service accounts de SPN de usuário em 5 minutos — kerberoasting.
3. *(Offline, invisível)* — atacante cracka o hash da service account mais fraca no Hashcat.
4. **4768** — requisição de TGT como a service account comprometida, de um host diferente.
5. **4624** LogonType 3 em um servidor de alto valor, AuthenticationPackage Kerberos, usando a service account.
6. [**7045**](/pt/blog/service-creation-event-id-7045) — serviço instalado para persistência sob a conta comprometida.

A rajada de 4769 no passo 2 é seu ponto de detecção mais cedo e mais barato — horas ou dias antes do atacante voltar como a service account.
