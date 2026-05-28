---
title: "Registo do PowerShell: o que se obtém com module logging e script block logging ligados"
description: "A diferença prática entre PowerShell module logging, script block logging, transcrições e buffers AMSI, e as definições GPO que realmente activam as úteis."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Qualquer toolkit de adversário digno de preocupação executa PowerShell em algum momento. Os beacons do Cobalt Strike lançam-no. O Empire e o Covenant são construídos com base nele. Os guias de living-off-the-land começam com ele. A boa notícia é que, desde o PowerShell 5.0, a Microsoft tem fornecido logging que, quando configurado correctamente, captura o texto literal de tudo o que o PowerShell executa, incluindo payloads ofuscados depois de desofuscados. A má notícia é que "quando configurado correctamente" está a fazer muito trabalho nessa frase. A maioria dos ambientes em que entro tem um dos quatro logs relevantes ligado, não os quatro, e não o mais útil.

Este artigo é o que se obtém de facto, o que vale a pena ligar, e onde estão as lacunas.

## Os quatro logs, por ordem de utilidade

O PowerShell escreve para `Microsoft-Windows-PowerShell%4Operational.evtx`. Os IDs de evento que importam:

- `4104` script block logging. O texto literal de cada script block que o PowerShell compila e executa. Se um block é sinalizado como suspeito pelas heurísticas integradas, é registado com gravidade Warning; caso contrário, com Verbose, que está desligado por defeito. Este é o evento que se quer.
- `4103` module logging. Regista a execução de pipeline por módulo, com binding de parâmetros. Menos prosa que `4104`, mais estruturado. Útil para "que cmdlets correram" sem o corpo do script.
- `4105` e `4106` pipeline iniciada e pipeline parada. Úteis para enquadramento, não para conteúdo.
- `400` / `403` (legacy, era PowerShell 2.0) mudanças de estado do engine. Os eventos forenses-históricos. Ainda se vêem em hosts onde alguém forçou um ataque de downgrade para PS 2.0.

Se só se puder ligar exactamente uma coisa, ligue-se `4104` em Verbose. Tudo o resto é suplementar.

## O que `4104` realmente captura

Um evento `4104` contém o texto completo de um script block tal como o PowerShell o compilou. Duas coisas decorrem de "tal como o PowerShell o compilou":

- O texto no evento é a representação *pós-desofuscação* na maioria dos casos. Se um operador executa `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`, obtém-se tanto a chamada externa `iex` (que é ela própria um `4104`) como um *segundo* `4104` para o script block descodificado interno, porque o PowerShell teve de compilar esse block para o executar. Esta é a propriedade individual mais valiosa do logging `4104`.
- Scripts grandes são divididos em múltiplos eventos usando `MessageNumber` e `MessageTotal` nos dados do evento. Um script de 50 KB torna-se uma cadeia de eventos que se tem de reagrupar antes da análise. A maioria das ferramentas faz isto; algumas não. Se o vosso parser está a mostrar fragmentos, verifiquem se trata a cadeia.

O campo `Path` mostra o ficheiro de origem se existia algum. `Path` vazio mais um corpo de script totalmente inlined equivale a "isto veio pela rede ou da memória" e é a melhor heurística para encontrar actividade de operador interactivo versus scripts agendados.

O `ScriptBlockId` é um GUID. Re-execuções do mesmo block no mesmo host normalmente reutilizam o GUID (por causa da cache), o que é conveniente para encontrar "todos os hosts onde este código correu" se se tiver um SIEM com pesquisa cross-host.

## Module logging: o que `4103` acrescenta

Module logging é mais antigo e mais ruidoso que script block logging. Engancha-se na camada de execução do pipeline, por isso para cada invocação de cmdlet num módulo registado obtém-se um `4103` com o nome do cmdlet, os parâmetros bound e uma string de payload.

No IR moderno, `4103` é mais útil em três casos:

- O atacante usou cmdlets que ligam parâmetros interessantes (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` mostra a fonte; `4103` mostra os valores dos parâmetros resolvidos após expansão de variáveis.
- O atacante usou encoded commands. `powershell -enc <base64>` produz um `4103` com o texto descodificado no payload antes do `4104` correspondente ser emitido.
- O atacante desactivou `4104` (é alcançável por edição de registo se tiverem admin local). `4103` vive sob um caminho de logging separado e às vezes fica ligado quando `4104` é silenciado.

A ressalva: module logging regista apenas os módulos explicitamente activados. A definição GPO quer ou `*` (registar tudo) ou uma lista de nomes de módulos. `*` é a resposta em qualquer ambiente que leve logging a sério. A objecção do "impacto na performance" que vão ouvir é real para workloads de PowerShell muito pesados e errada para desktops normais de frota.

## Transcrições não são script block logs

Há uma definição separada chamada "Turn on PowerShell Transcription" que escreve a entrada e saída de cada sessão para um ficheiro de texto sob um directório configurado. Isto não é a mesma coisa que `4104` e as pessoas baralham-nas constantemente.

As diferenças que importam:

- Transcrições incluem a *saída* de cmdlets. `4104` não. Se quiserem saber o que `Get-ADUser` realmente retornou, são as transcrições.
- Transcrições são ficheiros de texto. São trivialmente apagáveis e trivialmente modificáveis num host comprometido. Os eventos `4104` vão para um canal EVTX que requer limpeza de log ou pior para perturbar.
- Transcrições têm como destino por defeito a pasta de documentos do utilizador a menos que `OutputDirectory` seja definido. Se não definirem `OutputDirectory` para uma partilha de rede write-only, as transcrições não são prova; são uma cortesia.

Liguem as transcrições com `OutputDirectory` a apontar para um caminho UNC onde o utilizador que escreve tem permissões NTFS write-only (sem leitura, sem apagar). Isso dá-vos o rasto de saída de cmdlets que `4104` não dá, sem dar ao atacante a opção de alterar ou remover o seu próprio histórico.

## AMSI e o ângulo do buffer

AMSI (a Antimalware Scan Interface) é o hook de runtime que permite ao Defender e outros produtos AV inspeccionarem o conteúdo do script PowerShell antes da execução. Duas consequências para forense:

- Mesmo que o atacante desactive o logging do PowerShell, o AMSI ainda vê o conteúdo do script mesmo antes da execução, e o Defender vai registar um `1116` ou `1117` em `Microsoft-Windows-Windows Defender%4Operational.evtx` se o conteúdo corresponder a uma assinatura. O evento do Defender inclui o texto do script, parcialmente, no registo de detecção da ameaça. Em hosts onde script block logging estava desligado, este é por vezes o único lugar onde o código malicioso vive.
- As técnicas de "AMSI bypass" que os atacantes usam (patching de `amsi.dll!AmsiScanBuffer` em memória, fornecer um `AmsiContext` forjado, COM hijack do provider AMSI) elas próprias normalmente geram eventos `4104` para o código de bypass, *antes* do bypass entrar em efeito. O bypass não pode desligar o logging retroactivamente. Portanto, mesmo em hosts onde o operador neutralizou o AMSI com sucesso, o momento em que o fizeram está registado.

O padrão a procurar em `4104`: pequenos script blocks contendo as strings `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect`, ou `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`. Estas são as assinaturas de todos os bypasses comuns.

## Ligar o logging

As definições GPO vivem sob `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. As três que se querem activadas:

- "Turn on PowerShell Script Block Logging" activada. Marquem "Log script block invocation start / stop events" se quiserem os eventos `4105`/`4106` de enquadramento; desligado por defeito e geralmente não vale o volume.
- "Turn on Module Logging" activada. Nomes de módulos: `*`.
- "Turn on PowerShell Transcription" activada. `OutputDirectory`: um caminho UNC. `Include invocation headers`: marcado.

Os caminhos de registo correspondentes se os estiverem a definir fora de GPO:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

Apliquem às OUs que contêm máquinas que teriam de investigar. Isso é "todas elas" em qualquer organização séria.

## Como isto se parece durante uma investigação

Um comprometimento onde script block logging estava ligado diz-vos, por ordem:

1. O primeiro `4104` com um script block não-trivial vindo de um pai não-standard. Hora da primeira execução.
2. A cadeia de `4104`s à medida que o loader se desempacota. Cada camada de ofuscação descascada e registada.
3. Os cmdlets de runtime do framework C2 (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, todos os nomes de cmdlets ofensivos comuns e as suas variantes renomeadas).
4. Os comandos hands-on-keyboard do operador interactivo. Lêem-se como uma sessão de shell gravada, porque é o que são.

Cruzem com [Prefetch](https://www.prefetchparser.com) para encontrar quando `powershell.exe` correu, [ficheiros LNK](https://www.lnkparser.com) para ficheiros que o operador abriu, [AmCache](https://www.amcacheparser.com) para o hash do próprio binário PowerShell (às vezes é renomeado), e o [registo](https://www.registryparser.com) para o estado da GPO para confirmar que o logging estava de facto ligado na altura dos eventos que estão a ler.

Um comprometimento onde script block logging estava desligado diz-vos quase nada sobre PowerShell, e muito sobre a vossa postura de detecção. Corrijam isso primeiro.

## Leitura adicional

- Documentação Microsoft de [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows). A referência oficial.
- O post da FireEye / Mandiant [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility). Antigo mas ainda o writeup com perspectiva de campo mais limpo.
- Projecto [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) de Daniel Bohannon. O toolkit de desofuscação que complementa a análise de `4104`.
