---
title: "Event ID 4688 explicado: auditoria de criação de processos do Windows para DFIR"
description: "O 4688 é o registo de criação de processo do SO base, desde que a auditoria de linha de comandos esteja ligada. Eis o que contém, em que difere do Sysmon 1 e os padrões de triagem que valem o seu lugar."
date: "2026-05-24"
---

O Event ID **4688**, "Foi criado um novo processo", dispara no [canal `Security`](/pt/blog/what-is-an-evtx-file) sempre que um processo é lançado. É o mais próximo que o SO base chega da telemetria fornecida pelo [evento 1 do Sysmon](/pt/blog/sysmon-event-id-1-process-create), e em hosts onde o Sysmon não está implantado é a única fonte de `CommandLine` que tem. Num parque devidamente configurado, cada criação de processo é um destes. Leia-o bem e consegue responder a "o que correu" sem nunca abrir um EDR.

## Ligá-lo, porque o default está meio cego

Por defeito, o 4688 está ativado e o `CommandLine` **não** é capturado. Sem linhas de comando o registo diz-lhe um caminho de binário, um PID, um parent PID e nada sobre os argumentos. Para triagem é quase inútil. `powershell.exe` está bem. `powershell.exe -enc SQBFAFgA...` não está.

A correção é uma definição de Group Policy:

*Configuração do Computador / Modelos Administrativos / Sistema / Auditoria de Criação de Processos / Incluir linha de comandos nos eventos de criação de processos*

Ou o equivalente em registo: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Definido isto, cada 4688 transporta o campo `CommandLine` completo. O custo é volume de logs. O benefício é toda a superfície de investigação que existe abaixo do nome do binário. Ligue.

Também precisa da política de auditoria subjacente ligada: `auditpol /set /subcategory:"Process Creation" /success:enable`. Muitos hosts têm a política on e a linha de comandos off. Verifique ambas.

## O que o registo contém

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

Os campos que conduzem cada investigação:

- `CommandLine`. Argv completo (quando a GPO está on).
- `NewProcessName`. O caminho do binário. Combinado com `CommandLine` é a execução completa.
- `ParentProcessName`. O processo chamador. Office para cmd, browser para powershell, services para unsigned.exe são as cadeias-tipo.
- `SubjectUserName` e `SubjectLogonId`. Quem o lançou, sob que sessão. `SubjectLogonId` pivota para o [4624](/pt/blog/understanding-event-id-4624) que criou a sessão.
- `TokenElevationType`. `%%1936` Default (sem elevação), `%%1937` Full (consentimento UAC), `%%1938` Limited (filtrado). Um `1937` numa sessão não-admin é uma transição de privilégio que vale uma análise mais próxima.
- `MandatoryLabel`. SID de integridade. `S-1-16-12288` é High (elevado), `8192` Medium, `16384` System.

## 4688 vs Sysmon 1

Sobrepõem-se. Não são iguais.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sim (se GPO on) | Sim |
| Image / NewProcessName | Sim | Sim |
| Parent image | Sim (caminho) | Sim (caminho + CommandLine) |
| ParentCommandLine | Não | Sim |
| Image hashes (SHA/MD5/IMPHASH) | Não | Sim |
| ProcessGuid (estável entre hosts) | Não (PIDs reusam) | Sim |
| User SID + nome | Sim | Sim |
| Logon ID | Sim | Sim |
| CurrentDirectory | Não | Sim |
| Integrity level | Sim | Sim |
| Disponível sem instalar | Sim | Requer Sysmon |

Quando ambos estão presentes, o [Sysmon 1](/pt/blog/sysmon-event-id-1-process-create) é o registo mais rico. `ParentCommandLine`, hashes de imagem, `ProcessGuid` para cadeias parent-child estáveis. Quando só o 4688 está presente, constrói cadeias com PIDs, que o Windows reutiliza, portanto uma timeline longa pode conter ligações falsas. Cruze sempre ligações parent-child com timestamps. Quando não tem nenhum (sem Sysmon, sem auditoria de linha de comandos), [AmCache](https://www.amcacheparser.com), [prefetch](https://www.prefetchparser.com) e o [USN journal](https://www.usnparser.com) são a melhor evidência de execução a seguir.

## Os padrões que valem o seu lugar

1. **Office para shell**. `ParentProcessName` a terminar em `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` ou `mshta.exe`, com `NewProcessName` a ser `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` ou `regsvr32.exe`. Apps de documentos a spawn de shells é a cadeia clássica de macro/phishing.
2. **PowerShell encoded**. `NewProcessName` a terminar em `powershell.exe` e `CommandLine` a corresponder a `-enc`, `-encodedcommand`, `-e ` (letra única), `frombase64string`, `iex ` ou `invoke-expression`. Descodifique o payload. Cruze com o [registo 4104 scriptblock](/pt/blog/powershell-4104-scriptblock) para a mesma sessão.
3. **LOLBins de caminhos com escrita do utilizador**. Binários Microsoft assinados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lançados de `C:\Users\`, `%TEMP%` ou `C:\ProgramData\`. Uso legítimo nessas localizações é raro.
4. **svchost órfãos**. `svchost.exe` com `ParentProcessName` que não é `services.exe` (ou `wininit.exe` para boot muito cedo). O `svchost` real é sempre gerado por `services.exe`. Imitadores destacam-se.
5. **Binários renomeados**. `NewProcessName` a terminar em algo neutro (`update.exe`, `svc.exe`, `data.exe`) sob caminhos não-padrão. Combine com o campo `OriginalFileName` do Sysmon 1 quando disponível. Esse campo apanha PsExec, Mimikatz, binários Impacket renomeados que escapam à deteção simples baseada em nome.

## Sigma: Office para shell

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Office add-ins running approved scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL e Splunk

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Mapeamento ATT&CK

A maior parte da cobertura do 4688 cai sob T1059 Command and Scripting Interpreter e suas sub-técnicas (.001 PowerShell, .003 Windows Command Shell, .005 Visual Basic, .007 JavaScript). Padrões LOLBin mapeiam para T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32). Cadeias Office-para-shell mapeiam para T1566.001 Phishing: Spearphishing Attachment combinado com T1059. Deteções de binários renomeados mapeiam para T1036.003 Masquerading: Rename System Utilities.

## Falsos positivos, leia antes de alertar

- Agentes de update de software legitimamente fazem spawn de shells: Chocolatey, WinGet, wrappers MSI de fornecedores. Whitelist por `SubjectUserSid` (LocalSystem) mais padrões estáveis de `ParentProcessName` em vez de contas de utilizador.
- Vulnerability scanners e produtos EDR geram árvores de processos exatamente como um atacante a fazer recon: `net.exe`, `whoami.exe`, `systeminfo.exe`. Marque IPs de scanner e hosts.
- Boxes Citrix e RDS de multi-sessão veem cadeias legítimas `runas /netonly` para acesso cross-domain. Investigue o utilizador, não o padrão.
- Scripts de logon (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) disparam em cada logon e aparecem como cadeia recorrente. Baseline antes de alertar.

## O que o 4688 não lhe diz

Sem hash de ficheiro. Sem `ParentCommandLine`. Sem `ImageLoaded` (injeção de DLL não é uma criação de processo). Sem comportamento de rede. Para isso precisa do [evento 1 do Sysmon](/pt/blog/sysmon-event-id-1-process-create) (o 4688 mais rico), Sysmon 7 (image load), Sysmon 3/22 (network/DNS) e a telemetria comportamental de um EDR. O 4688 é o chão da visibilidade de processo. O mínimo que cada host Windows deve ter. Não é substituto de EDR adequado mais Sysmon nos hosts que importam.

## Onde o 4688 encaixa numa timeline

Para uma cadeia pós-exploração típica num host sem Sysmon:

1. [4624](/pt/blog/understanding-event-id-4624). Logon inicial, LogonType 3 de um IP externo.
2. 4624 outra vez. LogonType 9 (`runas /netonly`) sob o mesmo `SubjectLogonId`. Pivot de credenciais.
3. **4688**. `powershell.exe -enc ...` sob essa sessão.
4. [4104](/pt/blog/powershell-4104-scriptblock). Corpo do script descodificado, a buscar um payload de segunda fase.
5. **4688**. Binário de segunda fase a correr a partir de `%TEMP%`.
6. [7045](/pt/blog/service-creation-event-id-7045). Serviço instalado para persistência.

Seis registos contam a história inteira. Os PIDs em (3) e (5) ligam-se via `ProcessId` e `NewProcessId` do 4688, mas verifique por timestamp porque o Windows recicla PIDs. Com Sysmon presente, a cadeia `ProcessGuid` substitui essa correspondência frágil.

## Leitura adicional

- [Documentação Microsoft do 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
