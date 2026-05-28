---
title: "Event ID 4663 explicado: auditoria de acesso a ficheiros e registo com SACLs"
description: "O 4663 é o registo de auditoria de objeto por acesso. Configure SACLs nos ficheiros e chaves certas e tem um log por byte de quem tocou em quê. Útil para ransomware, exfil e roubo de credential-store."
date: "2026-05-24"
---

O Event ID **4663**, "Foi tentado um acesso a um objeto", dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que um ficheiro auditado, chave de registo ou objeto de kernel é tocado de forma que corresponda à sua System Access Control List. Ao contrário da maioria dos registos Security, o 4663 não produz nada por defeito. Tem de *configurar* a SACL no objeto primeiro. É por isso que a maioria dos ambientes não o tem. É também por isso que os que o têm levam uma vantagem quase injusta de deteção sobre um pequeno conjunto de técnicas.

Se instrumentar o 4663 em exatamente cinco coisas e ignorar o resto, vai apanhar staging de credential dumps, varreduras de ransomware e roubo de DPAPI mais barato que qualquer EDR.

## Onde dispara

No host que possui o objeto. SACLs de ficheiro disparam no file server. SACLs locais de registo disparam na workstation. SACLs de objetos AD disparam no DC. Não há registo central. Para visibilidade ao nível do parque numa share sensível, precisa de reencaminhar Security do file server que a aloja. Isto apanha gente desprevenida constantemente.

## Os campos do registo

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

Os que importam:

- `ObjectType`. `File`, `Key` (registo), `Process`, `Token`, `Directory`, `Section`. Qualquer classe de objeto que suporte SACLs.
- `ObjectName`. Caminho completo. Para ficheiros, caminho Windows. Para chaves de registo, caminho completo sob `\REGISTRY\MACHINE\...` (não o `HKLM\...` que escreveria no regedit).
- `AccessList`. O que foi tentado, como tokens de direito de acesso descodificados. Os comuns:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Bitmask em bruto dos `STANDARD_RIGHTS_*` e direitos específicos do objeto realmente pedidos.
- `ProcessName` e `ProcessId`. O processo que abriu o handle. Pivote para [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) para o contexto completo do processo.
- `SubjectLogonId`. Pivote para [4624](/pt/blog/understanding-event-id-4624) para a sessão de origem, o IP de origem se logon de rede, e o utilizador.

## Ativar o 4663 são três passos e há quem salte um

1. **Política de auditoria**. Ative as sub-políticas *Object Access* para File System e/ou Registry, sucesso e/ou falha. Group Policy ou `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL no objeto**. Propriedades, separador Security, Advanced, separador Auditing na GUI. Ou `Set-Acl`, `icacls /audit`. Especifica que principal, que direitos e se audita sucesso, falha ou ambos.
3. **Para o registo**, mesmo fluxo via Permissions da chave no regedit, Advanced, Auditing.

Sem (1) os registos nunca são escritos. Sem (2) o Windows não sabe que queria auditar alguma coisa. Sem (3) só está a auditar ficheiros. As pessoas saltam mais frequentemente o (2) porque o passo (1) parece chegar. Não chega.

As SACLs que valem o seu lugar em cada servidor:

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Audite `Everyone : ReadData : Success`. Qualquer coisa que leia estes que não seja `LocalSystem` é credential dumping.
- Ficheiros `*.dmp` em `C:\Windows\Temp` e `%TEMP%`. Audite `Everyone : WriteData : Success`. Um processo que escreva um `.dmp` aqui é ou o Windows após uma crash, ou um operador Mimikatz.
- `C:\ProgramData\Microsoft\Crypto\RSA` e `C:\Users\*\AppData\Roaming\Microsoft\Protect`. Diretórios de master-keys DPAPI. Audite `ReadData : Success`. Qualquer coisa que leia estes fora da sessão do próprio utilizador está a roubar segredos.
- `HKLM\SECURITY` e `HKLM\SAM`. Equivalentes no registo. Mesma auditoria.
- Shares sensíveis: financeira, jurídico, salários. Audite `WriteData + DELETE : Success` para apanhar varreduras de ransomware e apagamentos em massa.

## Os padrões que vai realmente apanhar

### Leitura da hive SAM ou SYSTEM

Qualquer 4663 com `ObjectName` a terminar em `\config\SAM`, `\config\SECURITY` ou `\config\SYSTEM`, em que `ProcessName` não é `services.exe`, `lsass.exe` ou `wininit.exe`, e `SubjectUserSid` não é `S-1-5-18`. Isto é `reg save HKLM\SAM`, `esentutl /y` contra uma shadow copy, ou qualquer ferramenta de credential dumping com acesso ao ficheiro da hive. Cruze com o [registry](https://www.registryparser.com) para ficheiros de hive de backup deixados para trás.

### Minidump LSASS escrito

Um 4663 `WriteData` para um ficheiro `.dmp` em `C:\Windows\Temp\`, `C:\ProgramData\` ou `%TEMP%`, com `ProcessName` de `rundll32.exe`, `procdump*.exe` ou qualquer coisa que chame `comsvcs.dll`. O manual é `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Cruze com [4688](/pt/blog/event-id-4688-process-creation) para a `CommandLine`. O 4663 apanha isto mesmo quando o EDR estava a dormir.

### Varredura de encriptação de ransomware

Muitos 4663s com `AccessMask` a incluir `WriteData + DELETE` contra ficheiros numa share sensível em segundos, todos do mesmo `SubjectLogonId` e `ProcessName`. Um processo de backup real toca em ficheiros num padrão modulado e mensurável. O ransomware varre uma árvore de diretórios o mais rápido que o disco permite. A forma denuncia-o.

### Roubo de master-key DPAPI

4663 `ReadData` em ficheiros sob `\AppData\Roaming\Microsoft\Protect\<sid>\` por qualquer processo que não seja a própria sessão do utilizador. O sinal indiscutível é `SubjectUserSid` ser um SID *diferente* do incorporado no caminho.

### Leitura de ficheiro de password de Group Policy Preferences

4663 `ReadData` em ficheiros que correspondem a `\SYSVOL\<domain>\Policies\*\Groups.xml`, ou `Services.xml`, `Drives.xml`, `ScheduledTasks.xml`. Isto é `Get-GPPPassword`. A técnica é antiga. Os ficheiros SYSVOL ainda existem com frequência em domínios legados, e ficaria surpreendido com a frequência com que alguém pega na chave AES ofuscada do MSDN e sai com uma credencial de domínio.

## Sigma: leitura da hive SAM

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

## KQL: varredura de encriptação de ransomware

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

100 ficheiros distintos escritos-ou-apagados por minuto sob uma sessão de logon é uma varredura. Ponto final.

## Splunk: acesso a master-key DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapeamento ATT&CK

- T1003.002 OS Credential Dumping: Security Account Manager. Leituras da hive SAM.
- T1003.004 LSA Secrets. Leituras da hive SECURITY.
- T1003.001 LSASS Memory. Escritas de `.dmp` (combinadas com contexto de processo).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Acesso a `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. Leituras de `Groups.xml` em SYSVOL.
- T1486 Data Encrypted for Impact. Padrões em massa de `WriteData + DELETE`.
- T1565.001 Stored Data Manipulation. Escritas arbitrárias em shares de dados monitorizadas.

## A armadilha do volume de SACL

Definir `Everyone : All access : Success+Failure` num diretório movimentado produz centenas de milhares de 4663s por minuto e enterra a recolha. SACLs são instrumentos de precisão. Audite:

- Apenas os tipos de acesso de que se importa. ReadData para credential stores. WriteData + DELETE para shares de dados. Raramente os dois ao mesmo tempo.
- Apenas sucesso. Falhas são mais raras e raramente interessantes neste corpus.
- Ficheiros específicos, não drives inteiras. O ficheiro SAM, não todo o `C:\Windows\System32\config\`. A share de RH, não todo o `D:\`.
- Principals específicos quando puder. Para objetos da classe SAM, `Everyone` está bem porque o acesso legítimo é por `LocalSystem` de qualquer maneira. Para dados partilhados, audite apenas os principals que mexem nos dados.

Uma SACL bem afinada em cinco objetos de alto valor produz 50 a 200 registos por dia por host. Inteiramente gerível.

## Falsos positivos que parecem idênticos a ataques

- Backups Volume Shadow Copy geram tráfego denso de 4663 durante uma janela de backup. Marque o `ProcessName` do orquestrador de backup.
- Scans on-access de antivírus abrem cada ficheiro num diretório alvo. As contas de serviço do produto AV vão dominar qualquer regra 4663 ingénua. Whitelist por SID.
- Serviços de indexação (Windows Search) atingem metadados via `ReadAttributes`. Geralmente filtrável por `AccessList`.
- Restauros em backup-staged parecem escritas de ransomware (muitos ficheiros, um processo, num diretório). O processo diz-lhe a diferença.
- A varredura em tempo real do Defender lê tudo. Se auditar demasiado, domina o ruído.

## O que o 4663 não lhe diz

- O conteúdo do acesso. Vê que um ficheiro foi lido ou escrito, não o que foi lido ou escrito. Para isso, EDR ou FIM.
- Porque é que o acesso aconteceu. Para correlacionar com intenção do utilizador, combine com [4688](/pt/blog/event-id-4688-process-creation) ou [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) para o contexto completo do processo chamador.
- Handles fechados. O 4663 dispara em handle *open*. Eventos de close são 4658, raramente úteis para deteção de ataques.
- Caminhos de rede de forma transparente. Acesso SMB a uma share dispara 4663 no *servidor*. O cliente não vê nada. Precisa de recolha do lado do servidor.
- Acessos falhados por defeito. Muitas lojas só auditam Success. Configure Failure apenas se realmente se importa com tentativas fracassadas.

## Onde o 4663 encaixa numa timeline

Cadeia clássica de dump de credenciais LSASS:

1. [4624](/pt/blog/understanding-event-id-4624). Logon admin, LogonType 3 ou 10.
2. [4672](/pt/blog/event-id-4672-special-privileges). SeDebugPrivilege concedido com a sessão.
3. [4688](/pt/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` para `C:\Windows\Temp\lsass.dmp` por `rundll32.exe`. Ouro forense. Prova de exfil em staging.
5. [4688](/pt/blog/event-id-4688-process-creation). Movimento ou arquivamento de ficheiro (operador a extrair o dump).
6. [1102](/pt/blog/event-id-1102-cleared-log). Log de Security limpo. Alguns operadores fazem isto. Muitos esquecem-se.

O passo 4 é o sinal mais barato e específico da cadeia. Identifica diretamente o artefacto de roubo de credenciais pelo nome, em disco, com o processo chamador anexado. Leituras de hive SAM, acesso a master-key DPAPI e leituras de SYSVOL Groups.xml funcionam da mesma forma.

## Leitura adicional

- [Documentação Microsoft do 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
