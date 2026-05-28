---
title: "Event ID 4768 explicado: pedidos de TGT Kerberos e AS-REP roasting"
description: "O 4768 é o registo do DC para cada TGT emitido. Lê-lo pelo código de resultado e flag de pré-autenticação revela AS-REP roasting, brute force e abuso de unconstrained delegation."
date: "2026-05-24"
---

O Event ID **4768**, "Foi pedido um ticket de autenticação Kerberos (TGT)", dispara num Domain Controller sempre que alguém pede um Ticket Granting Ticket. Cada logon de domínio começa com um destes. Combine-o com [4769](/pt/blog/event-id-4769-kerberoasting) (service ticket) e vê o ciclo de vida Kerberos inteiro de cada conta na floresta.

Num DC, o 4768 é o registo de maior volume no [canal Security](/pt/blog/what-is-an-evtx-file) depois do 4624. A maior parte é ruído. As fatias de alto sinal vivem em dois campos específicos, e um deles é a impressão digital do AS-REP roasting.

## Onde dispara

Tal como o [4769](/pt/blog/event-id-4769-kerberoasting), o 4768 aterra apenas no **Domain Controller** que emite. O cliente não o vê. O serviço alvo não o vê. Para detetar algo do 4768, precisa de recolha de Security de cada DC. Estilo KAPE para engagements únicos, WEF para regime contínuo.

## O que o registo contém

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

Os campos que importam:

- `TargetUserName`. A conta a pedir um TGT. Sempre uma conta de utilizador ou computador. `ServiceName` é sempre `krbtgt`.
- `Status`. Código de resultado Kerberos. `0x0` é sucesso. As falhas é que tornam o 4768 útil: `0x6` utilizador desconhecido, `0x12` cliente bloqueado, `0x17` password expirada, `0x18` password incorreta.
- `TicketEncryptionType`. Mesma codificação que o 4769: `0x12` e `0x11` AES (moderno), **`0x17` RC4** (legado, também a impressão digital do AS-REP roasting).
- `PreAuthType`. `2` é a pré-autenticação padrão por timestamp encriptado. `0` significa que **não foi usada pré-autenticação** (o pré-requisito para AS-REP roasting). `15`, `16`, `17` são valores de pré-autenticação baseada em certificado (PKINIT).
- `IpAddress`. Host requisitante. Combine com o [4624](/pt/blog/understanding-event-id-4624) do lado do cliente para contexto completo.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Preenchidos para PKINIT (smart-card ou logon por certificado). Vazios para logons baseados em password.

## Os dois padrões de ataque que o 4768 revela

### AS-REP roasting (T1558.004)

O uso de destaque. Algumas contas têm `DONT_REQUIRE_PREAUTH` definido em `userAccountControl` (UAC bit 22 = `0x400000`). Para essas contas, o DC responde ao pedido de TGT **sem** exigir a pré-autenticação por timestamp encriptado. O AS-REP que devolve contém material que um atacante pode descodificar offline para recuperar o hash da password da conta.

A impressão digital do 4768 de um AS-REP roast em curso:

- `PreAuthType = 0` (sem pré-autenticação).
- `TicketEncryptionType = 0x17` (RC4, o que a ferramenta de cracking precisa).
- `Status = 0x0` (o DC emitiu o AS-REP com prazer).
- Frequentemente em cluster. Um atacante junta dezenas de contas para testar quais têm pré-autenticação desativada.

Contas reais com `DONT_REQUIRE_PREAUTH` existem quase exclusivamente para compatibilidade legada: clientes Kerberos Unix muito antigos, alguns appliances arcaicos. São poucas em número e previsíveis em localização. Um 4768 com `PreAuthType=0` para uma conta que não tem nada que ver com Kerberos sem pré-autenticação é o sinal.

### Brute force ou spray de password

Falha de pré-autenticação Kerberos produz 4768 com `Status=0x18` ("password errada"). Ao contrário do [4625](/pt/blog/detecting-4625-brute-force) (que captura falhas NTLM), o 4768 é onde aterram ataques de password baseados em Kerberos. Toolkits modernos (Rubeus, kerbrute) falam Kerberos diretamente porque o DC falha silenciosamente em tentativas NTLM mais depressa do que responde a Kerberos, e muitos SOCs só vigiam o 4625.

A impressão digital de brute force no 4768:

- Muitos registos `Status=0x18` para o mesmo `TargetUserName` a partir do mesmo IP de origem dentro de uma janela curta. Brute force.
- Muitos registos `Status=0x18` em muitos valores de `TargetUserName` a partir de um IP de origem, cada um acertado uma ou duas vezes. Password spray.
- Um surto de `Status=0x6` ("utilizador desconhecido") a preceder `Status=0x18` da mesma origem. Enumeração de utilizadores confirmada antes do brute começar.

## Códigos de status que conduzem a triagem

| Status | Significado | Leitura do campo |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Sucesso. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Username não existe. Surtos = enumeração. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Conta bloqueada, desativada ou expirada. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Password expirada. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Password errada. Surtos = brute force ou spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Devolvido primeiro ao cliente num pedido de TGT novo. Sucesso real segue-se. Não alerte só com estes. |
| `0x25` | KRB_AP_ERR_SKEW | Desvio de relógio > 5 min. Frequentemente tentativas de AS-REP roasting a partir de um host com relógio deliberadamente errado. |

## Workflow de triagem: AS-REP roasting

1. Filtre 4768 em todos os DCs para `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Agrupe por `IpAddress`. Uma única conta a partir de um host de migração conhecido é configuração. Múltiplas contas a partir de uma origem é o ataque.
3. Pivote cada `TargetUserName` para o seu `userAccountControl`. O `DONT_REQUIRE_PREAUTH` realmente precisa de estar definido? Quase certamente não.
4. IP de origem para [4624](/pt/blog/understanding-event-id-4624) nesse host para encontrar a credencial que se autenticou para lançar o ataque.
5. Rode as passwords de cada conta crackeada. Remova `DONT_REQUIRE_PREAUTH` de contas que não precisam.

## Workflow de triagem: brute force Kerberos

1. Filtre 4768 por `Status == 0x18`.
2. Agrupe por `IpAddress` em janelas de 15 minutos. Conte `TargetUserName` distintos.
3. Mais de 5 contas a partir de uma origem em 15 minutos é spray. Mais de 10 falhas contra uma conta na mesma janela é brute force.
4. Cruze com `Status == 0x6` da mesma origem. Enumeração antes do brute é a ordem manual.

## Sigma: AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: spray de password Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapeamento ATT&CK

- T1558.004 AS-REP Roasting. Deteção principal em `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force e sub-técnicas `.001` Password Guessing e `.003` Password Spraying. Padrões de `Status=0x18`.
- T1558.001 Golden Ticket. Um TGT forjado contorna inteiramente o 4768. A deteção aqui é por *ausência*: um [4769](/pt/blog/event-id-4769-kerberoasting) sem um 4768 precedente da mesma origem e janela é a suspeita.
- T1187 Forced Authentication. Não diretamente visível no 4768, mas os pedidos de TGT resultantes ficarão.

## Falsos positivos que parecem ataques

- Stacks Java ou Unix Kerberos antigos em silos de apps legadas por vezes têm RC4 sem pré-autenticação por defeito. Aparecem como tráfego 4768 estável, em horas de expediente, a partir de um host estável. Baseline.
- Migração para PKINIT durante rollouts de smart-card. As mudanças legítimas para `PreAuthType=15/16/17` parecem anómalas se nunca as viu. Vigie a janela de rollout.
- Bugs de bibliotecas Kerberos. Certos clientes re-pedem TGTs agressivamente em desvio de relógio, gerando ruído. Cruze com `Status=0x25`.
- Travessia de trust de domínio. Autenticação cross-forest produz 4768 de cada lado. O `IpAddress` é um DC da outra floresta. Marque-o.

## O que o 4768 não lhe diz

O registo não inclui o material AS-REP que o atacante capturou (o que ele descodifica offline). Vê que o pedido foi emitido. Não vê que dados foram devolvidos além dos metadados. Também não vê a perspetiva do cliente: que aplicação lançou o pedido, em que contexto de utilizador correu. Para isso precisa do [4624](/pt/blog/understanding-event-id-4624) do lado do cliente, e do [4688](/pt/blog/event-id-4688-process-creation) se `kerbrute.exe` ou Rubeus correu localmente.

Note também que o 4768 dispara apenas para o pedido inicial de TGT e renovações. Uma vez que um cliente tem um TGT válido em cache, não fala com o KDC para TGT até renovar. Os tickets de serviço que daí derivam geram [4769](/pt/blog/event-id-4769-kerberoasting), não 4768. Um atacante que roube um TGT de longa duração (golden ticket) pode emitir 4769s arbitrários sem nunca produzir outro 4768.

## Onde o 4768 encaixa numa timeline

AS-REP roasting do princípio ao fim:

1. [4624](/pt/blog/understanding-event-id-4624). Logon de domínio inicial sem privilégios (credencial feita phishing).
2. *(LDAP, por vezes um 4662 se a SACL estiver definida)*. Atacante enumera `userAccountControl` para contas com `DONT_REQUIRE_PREAUTH`.
3. **4768** em surto. `PreAuthType=0`, `etype=0x17`, `Status=0x0` para cada conta candidata. O ponto de deteção.
4. *(Offline, invisível)*. Atacante descodifica o material AS-REP recuperado no Hashcat (modo 18200).
5. **4768**. Novo pedido de TGT como a conta comprometida, desta vez normalmente pré-autenticado.
6. [4769](/pt/blog/event-id-4769-kerberoasting). Tickets de serviço para tudo o que a conta comprometida pode alcançar.
7. [4624](/pt/blog/understanding-event-id-4624) LogonType 3 no serviço alvo.

O passo 3 é o canário. Do passo 5 em diante é o comprometimento real. A janela entre eles, minutos a dias, é a única janela em que um defensor pode agir antes da credencial estar viva no terreno.

## Leitura adicional

- [Documentação Microsoft do 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)
