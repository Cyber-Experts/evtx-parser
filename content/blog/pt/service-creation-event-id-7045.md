---
title: "Event ID 7045 explicado: instalação de serviço como sinal de persistência"
description: "Criação de serviço é uma das técnicas de persistência mais barulhentas. O event 7045 captura cada install — leia esses três campos e você pega a maior parte."
date: "2026-05-17"
---

O Event ID **7045** — "A service was installed in the system" — dispara no [canal `System`](/pt/blog/what-is-an-evtx-file) sempre que o Service Control Manager registra um novo serviço. É barulhento em um build stock (drivers, updates), mas em regime permanente de ambientes corporativos é quieto o bastante para que anomalias se destaquem. Também é uma das técnicas de persistência mais citadas do MITRE ATT&CK: T1543.003.

## O que o registro contém

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinco campos, três dos quais importam para IR.

## Os três campos para ler primeiro

**`ImagePath`** é o campo mais útil. Serviços legítimos vivem sob `C:\Windows\System32\`, `C:\Program Files\` ou `C:\Program Files (x86)\`. Qualquer serviço cujo binário fica em `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` ou um diretório de nome aleatório merece uma olhada. `ImagePath` também pode ser uma linha `cmd.exe /c …` ou `powershell.exe -e …` — essas são quase sempre maliciosas; serviços legítimos não chamam shell.

**`AccountName`** geralmente é `LocalSystem`. Um serviço instalado sob um usuário de domínio ou uma service account específica que não casa com o padrão da organização é incomum.

**`StartType`** de `auto start` significa que o serviço roda em todo boot. `demand start` significa manual. Persistência quase sempre quer `auto start`; execução lateral one-shot pode usar `demand start` e limpar atrás — fazendo do 7045 o único artefato restante.

## O padrão de execução lateral

Quando um atacante roda `PsExec` ou qualquer ferramenta que usa o SCM para remote-execute em outro host, você obtém um 7045 no host *alvo* com um `ImagePath` como `%SystemRoot%\PSEXESVC.exe` (padrão) ou um equivalente renomeado. O serviço aparece, roda e frequentemente é deletado em segundos. O 7045 é o fingerprint sobrevivente muito depois do serviço em si ter sumido.

Um 7045 com `ImagePath` terminando em `.exe` seguido segundos depois por [4624 LogonType **3**](/pt/blog/understanding-event-id-4624) de um host de origem específico é a assinatura escolar do PsExec. Variantes como SMBExec, WMIExec e `psexec.py` do Impacket produzem valores de `ImagePath` levemente diferentes, mas o mesmo padrão geral.

## O que 7045 não te diz

7045 dispara em *instalação*, não em cada start subsequente. Para ver o serviço efetivamente rodando você precisa de 7036 ("service entered the running state"). Para ver o processo subjacente você precisa do [Sysmon event 1](/pt/blog/sysmon-event-id-1-process-create) ou [4688](/pt/blog/event-id-4688-process-creation) com o caminho `Image` correspondente.

Para serviços instalados *antes* do log de auditoria começar (ex., durante install do SO), não há 7045 — eles existem no registry sob `HKLM\SYSTEM\CurrentControlSet\Services\` e têm que ser enumerados de lá, não de event logs.

## Workflow de triagem

1. Filtre o canal System por `EventID:7045`.
2. Sort ou pivote por `ImagePath` — qualquer coisa fora dos caminhos de install padrão é suspeita.
3. Para cada suspeito, puxe o 4624 correspondente por timestamp + host de origem — encontre a credencial que o instalou.
4. Puxe o Sysmon event 1 por `Image` casando com o `ImagePath` para ver execuções reais.
5. Note se uma sequência [**7036**](/pt/blog/event-id-7036-service-state) / 7034 / 7035 mostra uma execução one-shot ou um serviço persistente.

## Exemplo de regra Sigma — serviço instalado de caminho não padrão

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## Exemplo de KQL — fingerprint de execução lateral PsExec

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

Um 4624 LogonType-3 em 30 segundos de um 7045 no mesmo host é a assinatura escolar do PsExec.

## Exemplo de Splunk — instalador de serviço anômalo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mapeamento ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service**: o mapeamento de manchete. Serviços de longa duração iniciados sob binários controlados pelo atacante.
- **T1569.002 — System Services: Service Execution**: serviços de vida curta usados puramente como veículo para execução remota (PsExec, SMBExec, movimento lateral baseado em SCM).
- **T1078 — Valid Accounts**: quando o principal que instala é um domain admin cujas credenciais foram roubadas.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: serviços com display names imitando serviços Microsoft reais mas binários em outro lugar.

## Falsos positivos que parecem exatamente ataques

- **Instaladores de software** (Chocolatey, bootstrappers MSI) frequentemente instalam serviços de um diretório de staging antes de mover o binário. O 7045 dispara do caminho de staging mesmo que o install final seja limpo.
- **Agentes EDR / AV** instalam serviços como parte do setup. O `ImagePath` do vendor será estável e assinado; baseline.
- **Algumas atualizações Microsoft** instalam serviços de servicing temporários; são de vida curta e de `LocalSystem`.
- **Workloads container / Hyper-V** às vezes registram serviços transientes por VM.

O sinal é *one-off* installs em caminhos graváveis por usuário por instaladores *non-admin ou non-standard*. Um serviço de instalador assinado em `C:\Program Files\` não é o ataque.
