---
title: "Como abrir um arquivo .evtx (5 métodos, sem instalação obrigatória)"
description: "Cinco formas de abrir um arquivo .evtx do Windows — no navegador, no Event Viewer, com wevtutil, com EvtxECmd ou com python-evtx. Escolha pelo SO do host e pela fricção que você aguenta."
date: "2026-05-24"
howto:
  name: "Como abrir um arquivo .evtx"
  steps:
    - name: "Abra no navegador (sem instalação)"
      text: "Vá até a página inicial do EVTX parser e solte seu arquivo .evtx na zona de upload. O arquivo é processado localmente em um Web Worker usando um parser EVTX em Rust compilado para WebAssembly. Nada é enviado — desconecte sua rede se quiser confirmar. Funciona em Windows, macOS e Linux."
    - name: "Abra no Event Viewer (apenas Windows)"
      text: "Execute eventvwr.msc, escolha Action → Open Saved Log…, navegue até o arquivo .evtx, dê um nome à visão e clique em OK. Bom para navegar por um canal; fraco para filtrar entre milhares de registros."
    - name: "Despeje com wevtutil ou Get-WinEvent (linha de comando do Windows)"
      text: "Execute wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt para exportar todos os registros como texto. No PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 retorna objetos parseados que você pode encadear adiante."
    - name: "Faça parse com EvtxECmd (CLI multiplataforma)"
      text: "Baixe o EvtxECmd das ferramentas do Eric Zimmerman e execute EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv para achatar todos os registros (incluindo todos os campos de EventData) em uma linha de CSV por evento. Roda nativamente no Windows e em macOS/Linux via .NET."
    - name: "Faça script com python-evtx (Python multiplataforma)"
      text: "pip install python-evtx, depois execute python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml para obter cada registro como XML em stdout. Mais lento que o parser Rust, mas fácil de embutir em pipelines e em notebooks Jupyter."
---

Um arquivo `.evtx` é o formato binário do Windows Event Log ([o que tem dentro de um →](/pt/blog/what-is-an-evtx-file)). Você não consegue lê-lo com um editor de texto — é BinXML dentro de contêineres binários em chunks. Abaixo estão os cinco métodos que cobrem todos os casos realistas, em ordem do "solte o arquivo e está pronto" até "encaixe em um pipeline Python".

## Método 1 — abra no navegador (sem instalação)

O caminho mais rápido em qualquer sistema operacional: solte o `.evtx` no parser na [página inicial deste site](/pt). O arquivo é lido para a memória do seu navegador e processado localmente por um Web Worker rodando a crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilada para WebAssembly. Nada sai da sua máquina — você pode confirmar desconectando da rede antes de soltar o arquivo.

Você obtém a mesma visão por registro que uma ferramenta desktop produz: uma timeline filtrável, o `<EventData>` completo achatado na tabela, o XML completo a um clique e exportação CSV/JSON do conjunto filtrado. Melhor para triagem ad-hoc quando você não quer instalar nada, não quer subir nada, ou está em uma máquina que não é sua.

**Restrições.** Os limites de memória do navegador fazem com que arquivos maiores que ~500 MB fiquem lentos. Para logs arquivados de múltiplos gigabytes, desça para uma ferramenta nativa.

## Método 2 — Event Viewer (apenas Windows, nativo)

Toda instalação do Windows acompanha o Event Viewer. Inicie com `eventvwr.msc`, depois **Action → Open Saved Log…** e escolha o `.evtx`. O Event Viewer vai oferecer importar o arquivo para sua visão atual; aceite e você pode navegar nele como em qualquer canal ao vivo.

```text
Action → Open Saved Log… → Browse → select .evtx → OK
```

Bom para: navegar em um único arquivo, olhar a mensagem amigavelmente formatada de um registro, copiar e colar uma visão XML. Fraco para: filtrar milhares de registros (a UI fica lenta), exportação em massa ou executar queries que você quer scriptar.

## Método 3 — wevtutil / Get-WinEvent (linha de comando do Windows)

O `wevtutil` é a ferramenta nativa do Windows para gerenciamento de logs; o `Get-WinEvent` é sua contraparte em PowerShell. Ambos funcionam em arquivos `.evtx` salvos, não apenas em canais ao vivo.

Despeje todos os registros de um `.evtx` salvo para texto:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtre com XPath (aqui, todo 4624 nas últimas 24 horas):

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell com a mesma intenção, mas retornando objetos tipados:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Bom para: extração via script, jobs agendados, filtragem cirúrgica. O custo é a verbosidade — XPath contra XML é preciso mas não é amigável.

## Método 4 — EvtxECmd (CLI multiplataforma, o padrão de DFIR)

O [`EvtxECmd` do Eric Zimmerman](https://ericzimmerman.github.io/) é o parser padrão da maioria dos analistas de IR. Roda nativamente no Windows e em macOS / Linux sob .NET, faz parse mais rápido que o `wevtutil` e achata cada campo de `<EventData>` em uma coluna de CSV. Uma linha por registro.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Para uma pasta `winevt\Logs\` inteira em uma só passada, com maps que decodificam campos de eventos conhecidos em colunas amigáveis:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Bom para: parse em massa de coletas multi-arquivo, importar para um SIEM ou notebook, workflow de analista multiplataforma. O EvtxECmd é a resposta certa para quase toda tarefa do tipo "faça parse disto offline".

## Método 5 — python-evtx (encaixe em um pipeline)

Quando o arquivo precisa alimentar um pipeline Python, o [`python-evtx`](https://github.com/williballenthin/python-evtx) é o parser em Python puro.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

Em um notebook ou script:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Mais lento que a crate Rust (Python interpretado sobre chunks binários) mas a escolha certa quando você já está dentro de uma toolchain Python — notebooks forenses no Jupyter, jobs de threat hunting, enriquecimento customizado.

## Qual método usar e quando

- **Você só quer dar uma olhada no arquivo**: solte no [parser da página inicial](/pt). Caminho mais rápido, zero instalação.
- **Você está em um endpoint Windows com admin e o arquivo é pequeno**: Event Viewer.
- **Você precisa scriptar uma extração pontual**: `wevtutil` ou `Get-WinEvent`.
- **Você está fazendo DFIR de verdade em coletas multi-canal**: EvtxECmd.
- **Você está construindo um pipeline em Python**: `python-evtx`.

## Erros comuns e como lê-los

- **"The file does not appear to be valid"** no Event Viewer geralmente significa que o último chunk está sujo (o arquivo foi copiado enquanto o serviço EventLog ainda estava gravando). A maioria dos parsers lida com isso — tente [o parser no navegador](/pt) ou o `EvtxECmd`, que ambos reportam chunks sujos como aviso e seguem em frente.
- **"Access is denied"** do `wevtutil` contra um arquivo em `winevt\Logs\` é o serviço EventLog mantendo um lock exclusivo. Veja [coletando .evtx de um sistema ativo](/pt/blog/collecting-evtx-from-live-system) para as quatro formas padrão de contornar.
- **Saída vazia do `Get-WinEvent`** em um log salvo: passe o arquivo com `-Path`, não com `-LogName`. O `-LogName` só lê canais ao vivo.
- **PowerShell `Get-WinEvent` diz "No events were found that match the specified selection criteria"** — as chaves do seu `-FilterHashtable` são sensíveis a maiúsculas em algumas propriedades. Tente sem o filtro primeiro para confirmar que o arquivo faz parse.

Para um contexto sobre o que há de fato dentro de um `.evtx` e por que o formato é do jeito que é, veja [O que é um arquivo .evtx?](/pt/blog/what-is-an-evtx-file).
