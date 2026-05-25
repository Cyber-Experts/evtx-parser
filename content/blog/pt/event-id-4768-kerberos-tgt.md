---
title: "Event ID 4768 explicado: requisições de TGT Kerberos e AS-REP roasting"
description: "4768 é o registro do DC de cada TGT emitido. Leia-o pelo result code e pelo flag de pre-auth e você identifica AS-REP roasting, brute force e abuso de unconstrained delegation."
date: "2026-05-24"
---

O Event ID **4768** — "A Kerberos authentication ticket (TGT) was requested" — dispara em um Domain Controller toda vez que alguém pede um Ticket Granting Ticket. Todo logon de domínio começa com um desses. Combine com [4769](/pt/blog/event-id-4769-kerberoasting) (service ticket) e você vê o ciclo de vida Kerberos inteiro de toda conta na floresta.

Em um DC, 4768 é o registro de maior volume no [canal Security](/pt/blog/what-is-an-evtx-file) depois de 4624. A maior parte é ruído; as fatias de alto sinal vivem em dois campos específicos — e um deles é o fingerprint do AS-REP roasting.

## Onde dispara

Como [4769](/pt/blog/event-id-4769-kerberoasting), 4768 cai apenas no **Domain Controller** emissor. O cliente não vê; o serviço alvo não vê. Para detectar qualquer coisa de 4768, você precisa de coleta Security de todo DC — estilo KAPE para engajamentos pontuais, WEF para regime permanente.

## O que o registro contém

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

- **`TargetUserName`** — a conta requisitando um TGT. Sempre uma conta de usuário ou de computador; `ServiceName` é sempre `krbtgt`.
- **`Status`** — código de resultado Kerberos. `0x0` é sucesso. As falhas são o que torna 4768 útil: `0x6` = usuário desconhecido, `0x12` = cliente bloqueado, `0x17` = senha expirada, `0x18` = senha errada.
- **`TicketEncryptionType`** — mesma codificação do 4769: `0x12`/`0x11` AES (moderno), **`0x17` RC4** (legado, também o fingerprint do AS-REP roasting).
- **`PreAuthType`** — `2` é a pré-autenticação padrão de encrypted-timestamp; `0` significa **nenhuma pré-autenticação foi usada** (o pré-requisito do AS-REP roasting); `15`/`16`/`17` são valores de pré-autenticação baseados em certificado PKINIT.
- **`IpAddress`** — host requisitante. Combine com o [4624](/pt/blog/understanding-event-id-4624) do lado cliente para contexto completo.
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — preenchidos para PKINIT (logon de smart-card / certificado). Vazios para logons baseados em senha.

## Os dois padrões de ataque que 4768 revela

### 1. AS-REP roasting (T1558.004)

O uso de manchete. Algumas contas têm o flag `DONT_REQUIRE_PREAUTH` setado em `userAccountControl` (UAC bit 22 = `0x400000`). Para essas contas, o DC responde a uma requisição de TGT **sem** exigir a pré-autenticação de encrypted-timestamp — o que significa que o AS-REP que ele retorna contém material que um atacante pode crackear offline para recuperar o hash da senha da conta.

O fingerprint de 4768 de um AS-REP roast em andamento:

- `PreAuthType` é `0` (sem pré-auth).
- `TicketEncryptionType` é `0x17` (RC4 — o que a ferramenta de cracking precisa).
- `Status` é `0x0` (o DC alegremente emitiu o AS-REP).
- Frequentemente clusteriza: um atacante faz batch de dezenas de contas para testar quais têm pré-auth desabilitada.

Contas reais com `DONT_REQUIRE_PREAUTH` existem quase exclusivamente para compatibilidade legada (clientes Unix Kerberos muito antigos, alguns appliances antiquados). São pequenas em número e previsíveis em localização. Um 4768 com `PreAuthType=0` para uma conta que *não tem por que* usar Kerberos sem pré-auth é o sinal.

### 2. Brute force / spray baseado em senha

Falha de pré-auth Kerberos produz 4768 com `Status=0x18` ("senha errada"). Diferente de [4625](/pt/blog/detecting-4625-brute-force) (que captura falhas NTLM), 4768 é onde ataques de senha baseados em Kerberos caem. Toolkits modernos (Rubeus, kerbrute) falam Kerberos diretamente porque o DC silenciosamente falha em tentativas NTLM mais rápido do que responde às Kerberos — e muitos SOCs só observam 4625.

O fingerprint de brute force em 4768:

- Muitos registros `Status=0x18` para o mesmo `TargetUserName` da mesma origem em uma janela curta — brute force clássico.
- Muitos registros `Status=0x18` em muitos valores de `TargetUserName` da mesma origem, cada conta atingida uma ou duas vezes — password spray.
- Uma rajada de `Status=0x6` ("usuário desconhecido") precedendo um `Status=0x18` da mesma origem — enumeração de usuários confirmada antes do brute começar.

## Os códigos de Status que você verá

A lista completa é grande; estes são os que dirigem triagem:

| Status | Significado | O que geralmente significa no mundo real |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Sucesso. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Username não existe. Rajadas = enumeração. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Conta bloqueada / desabilitada / expirada. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Senha expirada. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Senha errada. Rajadas = brute force ou spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Retornado ao cliente *primeiro* em uma requisição fresca de TGT; um sucesso real se segue. Não alerte só com esses. |
| `0x25` | KRB_AP_ERR_SKEW | Clock skew > 5 min entre cliente e DC. Frequentemente tentativas de AS-REP roasting de um host com clock deliberadamente errado. |

## Workflow de triagem — AS-REP roasting

1. Filtre 4768 em todos os DCs por `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Agrupe por `IpAddress`. Conta única de um host de migração conhecido é configuração; múltiplas contas de uma origem é o ataque.
3. Pivote cada `TargetUserName` para seu `userAccountControl` — `DONT_REQUIRE_PREAUTH` precisa de fato estar setado? Quase certamente não.
4. IP de origem → [4624](/pt/blog/understanding-event-id-4624) nesse host para encontrar a credencial que autenticou para lançar o ataque.
5. Rotacione a senha de toda conta crackeada; remova `DONT_REQUIRE_PREAUTH` de contas que não precisam.

## Workflow de triagem — Kerberos brute force

1. Filtre 4768 por `Status == 0x18`.
2. Agrupe por `IpAddress` em janelas de 15 minutos; conte `TargetUserName` distintos.
3. >5 contas de uma origem em 15 minutos é spray; >10 falhas contra uma conta na mesma janela é brute force.
4. Cruze contra `Status == 0x6` da mesma origem — enumeração antes do brute é a ordem escolar.

## Exemplo de regra Sigma — AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## Exemplo de KQL — Kerberos password spray

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Exemplo de Splunk — AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapeamento ATT&CK

- **T1558.004 — AS-REP Roasting**: a detecção de manchete em `PreAuthType=0 + etype=0x17`.
- **T1110 — Brute Force** e sub-técnicas `.001` Password Guessing e `.003` Password Spraying — padrões `Status=0x18`.
- **T1558.001 — Golden Ticket**: um TGT forjado contorna 4768 inteiramente. Detecção aqui é por *ausência* — um [4769](/pt/blog/event-id-4769-kerberoasting) (requisição de TGS) sem 4768 precedente da mesma origem/janela é a suspeita.
- **T1187 — Forced Authentication**: não diretamente visível em 4768, mas as requisições de TGT resultantes serão.

## Falsos positivos que parecem ataques

- **Stacks Java / Unix Kerberos antigos** em silos de apps legados às vezes default para RC4 sem pré-auth. Aparecem como tráfego constante e diurno de 4768 de um host estável. Baseline.
- **Migração PKINIT** durante rollouts de smart-card: flips legítimos `PreAuthType=15/16/17` parecem anômalos se você não os viu antes. Observe a janela de rollout.
- **Bugs de biblioteca Kerberos**: certos clientes re-requisitam TGTs agressivamente em time skew, gerando ruído. Cruze com `Status=0x25`.
- **Travessia de trust de domínio**: autenticação cross-forest produz 4768 em cada lado. O `IpAddress` será um DC da outra floresta; marque-o.

## O que 4768 não te diz

O registro **não** inclui o material AS-REP real que o atacante capturou (que é o que ele cracka offline). Você vê que a requisição foi emitida; não vê que dados foram retornados além do metadado. Também não vê a perspectiva do *cliente* — qual aplicação lançou a requisição, em qual contexto de usuário rodou, etc. Para isso você precisa do [4624](/pt/blog/understanding-event-id-4624) do lado cliente (e [4688](/pt/blog/event-id-4688-process-creation) se `kerbrute.exe` rodou localmente).

Note também que 4768 dispara apenas para a requisição *inicial* de TGT e em renovações. Uma vez que um cliente tem um TGT válido em cache, ele não fala com o KDC novamente para TGT até a renovação; os tickets de *serviço* que ele deriva geram [4769](/pt/blog/event-id-4769-kerberoasting), não 4768. Os dois registros descrevem estágios diferentes do mesmo protocolo — e um atacante que rouba um TGT de longa duração (golden ticket) pode emitir 4769s arbitrários sem nunca produzir outro 4768.

## Onde 4768 se encaixa em uma timeline

A cadeia de AS-REP roasting do início ao fim:

1. [**4624**](/pt/blog/understanding-event-id-4624) — logon de domínio inicial de baixo privilégio (credencial phisheada).
2. *(LDAP, às vezes um 4662 se SACL estiver setada)* — atacante enumera flags `userAccountControl` para contas com `DONT_REQUIRE_PREAUTH`.
3. **4768** burst — `PreAuthType=0`, `etype=0x17`, `Status=0x0` para cada conta candidata. **Esse é o ponto de detecção.**
4. *(Offline, invisível)* — atacante cracka o material AS-REP recuperado no Hashcat (modo 18200) e recupera a senha em texto plano.
5. **4768** — nova requisição de TGT como a conta comprometida, dessa vez com pré-auth normal.
6. [**4769**](/pt/blog/event-id-4769-kerberoasting) — service tickets para tudo que a conta comprometida pode alcançar.
7. [**4624**](/pt/blog/understanding-event-id-4624) LogonType 3 no serviço alvo.

Passo 3 é o canário. Passo 5 em diante é o comprometimento real. A janela entre eles — minutos a dias — é a única janela onde um defensor pode agir antes da credencial estar viva no mundo real.
