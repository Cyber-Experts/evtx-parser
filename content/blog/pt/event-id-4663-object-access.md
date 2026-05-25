---
title: "Event ID 4663 explicado: auditoria de acesso a arquivos e registry com SACLs"
description: "4663 é o registro de auditoria por acesso a objeto. Configure SACLs nos arquivos e chaves certos e você ganha um log de quem tocou o quê — ransomware, exfil, roubo de credenciais."
date: "2026-05-24"
---

O Event ID **4663** — "An attempt was made to access an object" — dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) toda vez que um arquivo, chave de registry ou objeto de kernel auditado é acessado de uma forma que combina com sua System Access Control List (SACL). Diferente da maioria dos registros Security, 4663 não produz nada por si só — você precisa *configurar* a SACL no objeto que importa antes que qualquer 4663 exista. Isso o torna barato por padrão e devastadoramente efetivo uma vez ajustado.

Se você só auditar uma coisa com 4663, audite acesso a credential stores e shares de dados de alto valor. A relação sinal-ruído está entre as melhores em todo o catálogo de auditoria.

## Onde dispara

Sempre no host que possui o objeto — o file server para uma SACL de arquivo, a estação para uma SACL de registry local, o DC para uma SACL de objeto AD. Não há registro central; se você quer visibilidade em todo o ambiente em um share sensível, precisa encaminhar `Security` do file server que o hospeda.

## O que o registro contém

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

Os campos:

- **`ObjectType`** — `File`, `Key` (registry), `Process`, `Token`, `Directory`, `Section` ou qualquer classe de objeto que suporte SACLs.
- **`ObjectName`** — o caminho completo. Para arquivos é um caminho Windows; para chaves de registry, o caminho completo sob `\REGISTRY\MACHINE\…` (nota: não a notação `HKLM\…` que você digitaria no regedit).
- **`AccessList`** — o que foi tentado, como uma lista de nomes decodificados de access-rights (um por token `%%NNNN`). Os valores decodificados comuns:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — o bitmask bruto de `STANDARD_RIGHTS_*` e direitos específicos do objeto efetivamente requisitados.
- **`ProcessName`** + **`ProcessId`** — o processo que abriu o handle. O pivot para [4688](/pt/blog/event-id-4688-process-creation) / [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) para o contexto completo do processo.
- **`SubjectLogonId`** — pivot para [4624](/pt/blog/understanding-event-id-4624) para a sessão de origem, o IP de origem se for logon de rede, e o usuário.

## Configurando 4663 — a parte que realmente é trabalho

Há três camadas de configuração; faltando qualquer uma significa nenhum registro.

1. **Política de auditoria**: habilite *Object Access → Audit File System* e/ou *Audit Registry* para success e/ou failure. Via Group Policy ou `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL no objeto**: botão direito → Properties → Security → Advanced → aba Auditing (GUI do Windows), ou via `Set-Acl` / `icacls /audit`. Você especifica *qual principal* (frequentemente `Everyone` ou `Authenticated Users`), *quais direitos*, e *se auditar success, failure, ou ambos*.
3. **Para registry**: mesmo fluxo, acessado via `regedit` → chave → Permissions → Advanced → Auditing.

Sem (1) os registros nunca são escritos. Sem (2) o Windows não tem ideia de que você queria auditar nada. Sem (3) você só está auditando arquivos.

As SACLs para definir em cada servidor:

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — credential stores locais. Audite `Everyone : ReadData : Success`. Qualquer coisa lendo isso além de `LocalSystem` é uma tentativa de credential-dumping.
- **`%TEMP%\lsass.dmp`** e qualquer `*.dmp` em `C:\Windows\Temp` — minidumps de processo. Audite `Everyone : WriteData : Success`. Um processo escrevendo um `.dmp` aqui é ou um crash dump (Windows) ou um operador de Mimikatz (todos os outros).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** e **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — diretórios de master-key DPAPI. Audite `ReadData : Success`. Qualquer um lendo isso fora da própria sessão do usuário está roubando segredos protegidos.
- **`HKLM\SECURITY`** e **`HKLM\SAM`** — equivalentes em registry. Audite `ReadData : Success`.
- **File shares sensíveis** — finanças, jurídico, payroll. Audite `WriteData + DELETE : Success` para pegar varreduras de criptografia de ransomware e exclusões em massa.

## Os padrões de triagem

### 1. Leitura de hive SAM / SYSTEM

Qualquer 4663 com `ObjectName` terminando em `\config\SAM`, `\config\SECURITY` ou `\config\SYSTEM`, onde `ProcessName` não é `services.exe` / `lsass.exe` / `wininit.exe` e `SubjectUserSid` não é `S-1-5-18`. Isso é `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy` ou qualquer ferramenta de credential-dumping com acesso em nível de arquivo às hives.

### 2. Arquivo de dump do LSASS escrito

Um 4663 `WriteData` para um arquivo `.dmp` em `C:\Windows\Temp\`, `C:\ProgramData\` ou `%TEMP%`, com `ProcessName` de `rundll32.exe`, `procdump*.exe`, chamadores relacionados a `comsvcs.dll` ou um binário renomeado. Esse é o padrão de minidump de LSASS. Cross-reference com [4688](/pt/blog/event-id-4688-process-creation) para o `CommandLine` — `comsvcs.dll MiniDump` é a codificação mais comum.

### 3. Varredura de criptografia de ransomware

Muitos 4663s com `AccessMask` incluindo `WriteData + DELETE` contra arquivos em um share sensível em segundos, todos do mesmo `SubjectLogonId` e `ProcessName`. Um processo de backup real toca arquivos em um padrão mensurável e throttled; ransomware varre uma árvore de diretórios tão rápido quanto o disco permite.

### 4. Roubo de master-key DPAPI

4663 `ReadData` em arquivos sob `\AppData\Roaming\Microsoft\Protect\<sid>\` por qualquer processo que não seja a própria sessão do usuário. O padrão clássico é `SubjectUserSid` sendo um SID *diferente* daquele no caminho.

### 5. Leitura de arquivo de senha de Group Policy preference

4663 `ReadData` em arquivos correspondendo a `\SYSVOL\<domain>\Policies\*\Groups.xml` (ou `Services.xml`, `Drives.xml`). Esse é o ataque `Get-GPPPassword` — antigo, mas os arquivos SYSVOL frequentemente ainda existem em domínios legados.

## Exemplo de regra Sigma — leitura de hive SAM

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## Exemplo de KQL — varredura de criptografia de ransomware

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

100 arquivos distintos escritos-ou-deletados por minuto sob uma sessão de logon é uma varredura, ponto final.

## Exemplo de Splunk — acesso a master-key DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapeamento ATT&CK

- **T1003.002 — OS Credential Dumping: Security Account Manager**: leituras da hive SAM.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: leituras da hive SECURITY.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: escritas de `.dmp` (combinadas com contexto de processo).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**: acesso a `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**: leituras de `Groups.xml` em SYSVOL.
- **T1486 — Data Encrypted for Impact**: padrões em massa de WriteData + DELETE (ransomware).
- **T1565.001 — Stored Data Manipulation**: escritas arbitrárias em shares de dados monitorados.

## Gestão de volume — a armadilha das SACLs

Definir ingenuamente `Everyone : All access : Success+Failure` em um diretório movimentado produzirá centenas de milhares de registros 4663 por minuto e enterrará sua coleta. SACLs são instrumentos de precisão. Audite:

- **Apenas os tipos de acesso que importam** (`ReadData` para credential stores; `WriteData + DELETE` para data shares; raramente ambos).
- **Apenas success** — falhas são mais raras e raramente interessantes.
- **Arquivos específicos**, não drives inteiros. O arquivo SAM, não todo `C:\Windows\System32\config\`. O share de RH, não todo `D:\`.
- **Principais específicos** quando puder — para objetos da classe SAM, `Everyone` é OK porque acesso legítimo é via `LocalSystem` mesmo; para dados compartilhados, audite apenas os principais que de fato tocam os dados.

Uma SACL bem ajustada em cinco objetos de alto valor produz 50-200 registros por dia por host — totalmente tratável.

## Falsos positivos que parecem exatamente ataques

- **Volume Shadow Copy** (VSS) backups geram tráfego denso de 4663 durante uma janela de backup. Marque o `ProcessName` do orquestrador de backup.
- **Scans on-access de antivírus** abrem cada arquivo em um diretório alvo; service accounts de produtos AV dominarão qualquer regra ingênua de 4663. Whitelist por SID.
- **Serviços de indexação** (Windows Search, estilo Spotlight) batem em metadados via `ReadAttributes` — geralmente filtráveis por `AccessList`.
- **Restores stageados de backup** parecem escritas de ransomware (muitos arquivos, um processo, em um diretório), mas o processo é seu agente de backup.
- **Scan em tempo real do Defender** lê tudo; se você auditar amplamente demais, é a fonte de ruído dominante.

## O que 4663 não te diz

- **Conteúdo do acesso**: você vê que um arquivo foi lido/escrito, não o que foi lido/escrito. Para isso você precisa de um produto EDR ou FIM (File Integrity Monitoring).
- **Por que o acesso aconteceu**: apenas o resultado da syscall. Para correlacionar com a intenção do usuário, combine com [4688](/pt/blog/event-id-4688-process-creation) / [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) para o contexto completo do processo chamador.
- **Handles fechados**: 4663 dispara na *abertura* do handle. Eventos de fechamento são 4658, raramente úteis para detecção de ataque.
- **Caminhos de rede transparentemente**: acesso SMB a um share dispara 4663 no *servidor*; o cliente não vê nada. Você precisa de coleta server-side.
- **Acesso negado por padrão**: muitas operações só auditam `Success`; configure `Failure` apenas se você genuinamente se importa com tentativas de acesso frustradas.

## Onde 4663 se encaixa em uma timeline

Cadeia clássica de credential dump de LSASS:

1. [**4624**](/pt/blog/understanding-event-id-4624) — logon de admin (LogonType 3 ou 10).
2. [**4672**](/pt/blog/event-id-4672-special-privileges) — SeDebugPrivilege concedido com a sessão.
3. [**4688**](/pt/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` em `C:\Windows\Temp\lsass.dmp` por `rundll32.exe`. **Ouro forense — prova de staging de exfil.**
5. [**4688**](/pt/blog/event-id-4688-process-creation) — move / archive de arquivo (o operador extraindo o dump).
6. [**1102**](/pt/blog/event-id-1102-cleared-log) — Security log limpo (alguns operadores fazem isso; muitos esquecem).

O 4663 no passo 4 é o sinal mais barato e mais específico na cadeia — identifica diretamente o artefato de roubo de credencial pelo nome, em disco, com o processo chamador anexado. Leituras de hive SAM, acesso a master-key DPAPI e leituras de Groups.xml em SYSVOL funcionam da mesma forma.
