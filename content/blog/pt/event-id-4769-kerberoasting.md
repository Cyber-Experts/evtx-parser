---
title: "Event ID 4769 explicado: tickets de serviço Kerberos e kerberoasting"
description: "O 4769 é o registo do DC de cada pedido de service ticket. Lê-lo pelo tipo de encriptação e revela kerberoasting. Lê-lo com o 4768 e revela pass-the-ticket."
date: "2026-05-24"
---

O Event ID **4769**, "Foi pedido um service ticket Kerberos", dispara em cada Domain Controller sempre que qualquer conta pede um ticket TGS (Ticket Granting Service) para um serviço. Cada ligação SMB, cada login SQL, cada acerto SSO web produz um no DC que tratou do pedido. É o registo de maior volume no [canal Security](/pt/blog/what-is-an-evtx-file) num DC ocupado, e o único sítio onde o kerberoasting aparece de forma fiável antes de as credenciais serem crackeadas offline.

Se só instrumentar três registos de Security dos seus DCs, este é um deles.

## Onde vive

O `4769` é escrito no canal Security apenas do **Domain Controller** que o emite. Não no cliente, não no serviço alvo. Para ver todos os registos 4769 de um domínio, tem de recolher de cada DC. O target `EventLogs` do KAPE num DC, ou o reencaminhamento de Security via WEF para um coletor, ambos funcionam. WEF é o que as lojas maduras usam.

## O que o registo contém

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

Os campos que conduzem a triagem:

- `TargetUserName`. O requisitante (a conta de utilizador, em formato `user@DOMAIN`).
- `ServiceName`. O SPN pedido. Uma conta de utilizador aqui (em vez de `host/...` ou uma classe de serviço) é suspeito.
- `TicketEncryptionType`. O campo que decide se este registo importa. Domínios modernos correm `0x12` (AES-256-CTS-HMAC-SHA1-96) ou `0x11` (AES-128). **`0x17` é RC4-HMAC**: legado, fraco, e o *único* tipo de encriptação que os modos `kerberoast` do Mimikatz e Rubeus pedem. Um 4769 para um ticket de conta de serviço com `0x17` é uma impressão digital manual de kerberoasting.
- `Status`. `0x0` é sucesso. Qualquer outro valor é negado (códigos documentados em `[MS-KILE]`).
- `IpAddress`. Host requisitante. Combine com o [4624](/pt/blog/understanding-event-id-4624) nesse host para ver o logon que produziu a sessão.

## TicketEncryptionType: o campo que decide

| Valor | Algoritmo | Estado |
|---|---|---|
| 0x01 | DES-CBC-CRC | Desativado por defeito desde Win7 |
| 0x03 | DES-CBC-MD5 | Desativado por defeito desde Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (default para a maioria das contas) |
| **0x17** | **RC4-HMAC-MD5** | **Legado. Necessário para kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 export-grade, raríssimo |

Se o domínio tiver sido baselined e o `msDS-SupportedEncryptionTypes` definido para AES-only em contas de serviço, o `0x17` não devia aparecer para essas contas de todo. Atacantes pedem `0x17` explicitamente porque crackear service tickets RC4 é barato computacionalmente. AES não é. A ferramenta de cracking *tem* de pedir 0x17.

Este é o campo de sinal mais alto no registo.

## O padrão do kerberoasting

Kerberoasting (T1558.003) funciona assim:

1. Atacante autentica com qualquer utilizador de domínio (não precisa de admin).
2. Atacante enumera SPNs registados em contas de utilizador (não contas de computador), tipicamente via LDAP `(servicePrincipalName=*)` filtrado a objetos de utilizador.
3. Atacante pede um TGS para cada SPN com `etype=23` (RC4) via o protocolo Kerberos padrão. O 4769 que está à procura.
4. O DC emite o ticket com prazer, encriptado com o hash NTLM da conta de serviço.
5. Atacante puxa o blob encriptado e crackeia-o offline no Hashcat (`-m 13100`).

A impressão digital no 4769:

- `ServiceName` é `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` ou qualquer SPN a apontar para uma conta de utilizador (não `host/...` ou `cifs/...`, que são contas de computador).
- `TicketEncryptionType` é `0x17`.
- Um surto dentro de uma janela curta, da mesma origem, para muitos SPNs.

Um padrão relacionado, **AS-REP roasting** (T1558.004), usa o [4768](/pt/blog/event-id-4768-kerberos-tgt) em vez disso, visando contas com `DONT_REQUIRE_PREAUTH`. Registo diferente, mesma família.

## Pass-the-ticket, golden, silver

O 4769 também revela forjamento de tickets, mas o sinal é mais subtil.

- Um 4769 *sem* um 4768 precedente para o mesmo `LogonGuid` a partir do mesmo host numa janela razoável: suspeita de golden ticket. O atacante apresentou um TGT forjado e foi direto a pedidos de TGS.
- Um 4769 *e* a autenticação de serviço resultante no alvo *sem* um 4769 visível em qualquer DC: suspeita de silver ticket. O atacante forjou o próprio TGS. O DC nunca foi consultado.
- Mismatch de `LogonGuid` entre o 4624 no alvo e o 4769 supostamente a emitir o ticket: ticket forjado.

Estes são padrões de deteção por ausência. Requerem cobertura completa de logs em todos os DCs e serviços alvo. Lacunas na cobertura WEF produzem falsos positivos com aparência idêntica. Caracterize a sua recolha antes de alertar.

## Workflow de triagem

1. Filtre todos os 4769 no corpus de DCs por `TicketEncryptionType == 0x17`.
2. Agrupe por `IpAddress` e `TargetUserName` em janelas de 30 minutos. Conte `ServiceName` distintos por origem.
3. Mais de 3 SPNs distintos pedidos como 0x17 de uma origem em 30 minutos é kerberoasting em quase todo o lado.
4. Pivote o IP de origem para o seu [4624](/pt/blog/understanding-event-id-4624) para encontrar a credencial que iniciou o ataque.
5. Pivote os SPNs pedidos para as contas de serviço proprietárias. Rode essas passwords. Faça reset a hashes crackeados em horas, não em dias.

## Sigma

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

O `filter_machine` exclui SPNs de contas de computador (que terminam sempre em `$`). Kerberoasting visa apenas SPNs de contas de utilizador.

## KQL e Splunk

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

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapeamento ATT&CK

- T1558.003 Kerberoasting. O título.
- T1558.001 Golden Ticket. 4769 sem 4768 do mesmo `LogonGuid`.
- T1558.002 Silver Ticket. 4769 ausente para uma autenticação de serviço observada no alvo.
- T1078 Valid Accounts. 4769 a partir de um IP inesperado para uma conta de serviço conhecida.
- T1550.003 Pass the Ticket. 4769 seguido por [4624](/pt/blog/understanding-event-id-4624) LogonType 3 com `LogonProcessName: Kerberos`.

## Falsos positivos que vai ver

- Aplicações legadas (alguns conectores antigos de SQL Server, certas apps Java/JBoss) pedem RC4 explicitamente. 0x17 estável, em horas de expediente, a partir de um conjunto pequeno de hosts estáveis. Baseline e exclua.
- Domínios pré-AES durante uma transição de hardening Kerberos emitem 0x17 amplamente até `msDS-SupportedEncryptionTypes` estar definido em cada conta. Incómodo. Não malicioso.
- Vulnerability scanners (Tenable, Qualys, scripts de enumeração BloodHound) replicam tráfego de kerberoasting. Marque hosts de scanner.
- Ferramentas de migração de contas durante movimentações cross-forest podem pedir combinações invulgares.

O sinal é o padrão de *surto*, não o registo individual. 0x17 estável de um host é configuração. 0x17 em surto para muitos SPNs de um host em minutos é o ataque.

## O que o 4769 não lhe diz

O registo não inclui o ticket encriptado em si. O cracking acontece sobre o que o atacante exfiltrou, não na rede a partir do DC. Não consegue, só com o 4769, distinguir "ticket foi emitido e nunca usado" de "ticket foi crackeado, credenciais reutilizadas". Para a segunda metade da cadeia precisa do [4624](/pt/blog/understanding-event-id-4624) resultante no serviço alvo (LogonType 3, AuthenticationPackage Kerberos), e idealmente [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) a mostrar o que correu depois da credencial ser reutilizada. Trate o 4769 como canário, não como alarme.

## Onde o 4769 encaixa numa timeline

Cadeia clássica de kerberoasting pós-exploração:

1. [4624](/pt/blog/understanding-event-id-4624) numa workstation. Acesso inicial via credenciais de utilizador feito phishing.
2. **4769** ×N dessa workstation para um DC, todos `etype=0x17`, todos a visar contas de serviço com SPN de utilizador em 5 minutos. Kerberoasting.
3. *(Offline, invisível)*. Atacante crackeia o hash da conta de serviço mais fraca no Hashcat.
4. [4768](/pt/blog/event-id-4768-kerberos-tgt). Pedido de TGT como a conta de serviço comprometida, a partir de um host diferente.
5. 4624 LogonType 3 num servidor de alto valor, AuthenticationPackage Kerberos.
6. [7045](/pt/blog/service-creation-event-id-7045). Serviço instalado para persistência sob a conta comprometida.

O surto de 4769 no passo 2 é o seu ponto de deteção mais precoce e mais barato. Horas ou dias antes do atacante voltar como a conta de serviço.

## Leitura adicional

- [Documentação Microsoft do 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)
