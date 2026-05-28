---
title: "Como abrir um ficheiro .evtx (5 métodos, sem instalação)"
description: "Cinco formas de abrir um ficheiro .evtx do Windows: no browser, no Event Viewer, com wevtutil, com EvtxECmd ou com python-evtx. Escolha pelo SO do host e pela fricção que aguenta."
date: "2026-05-24"
howto:
  name: "Como abrir um ficheiro .evtx"
  steps:
    - name: "Abrir no browser (sem instalação)"
      text: "Vá à página inicial do parser EVTX, largue o seu ficheiro .evtx na zona de upload. O ficheiro é parsado localmente num Web Worker usando um parser EVTX em Rust compilado para WebAssembly. Nada é enviado. Funciona em Windows, macOS e Linux."
    - name: "Abrir no Event Viewer (só Windows)"
      text: "Inicie eventvwr.msc, escolha Action e depois Open Saved Log, navegue até ao ficheiro .evtx, dê nome à vista e clique OK. Bom para navegar num canal; fraco para filtrar entre milhares de registos."
    - name: "Despejar com wevtutil ou Get-WinEvent (linha de comandos do Windows)"
      text: "Execute wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt para exportar cada registo como texto. Em PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 devolve objetos parsed que pode encadear mais."
    - name: "Parsar com EvtxECmd (CLI multiplataforma)"
      text: "Descarregue o EvtxECmd das ferramentas de Eric Zimmerman e corra EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv para achatar cada registo (incluindo todos os campos EventData) numa linha CSV por evento."
    - name: "Programar com python-evtx (Python multiplataforma)"
      text: "pip install python-evtx, depois corra python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml para obter cada registo como XML em stdout. Mais lento que o parser Rust mas fácil de incluir em pipelines e Jupyter notebooks."
---

Um ficheiro `.evtx` é o formato binário do log de eventos do Windows ([o que tem lá dentro](/pt/blog/what-is-an-evtx-file)). Não o consegue ler com um editor de texto. É BinXML dentro de contentores binários em chunks. Há cinco métodos que cobrem cada caso realista, aproximadamente por ordem de "larga o ficheiro e está feito" até "ligar a um pipeline Python".

## Método 1: abri-lo no browser, sem instalação

O caminho mais rápido em qualquer sistema operativo. Largue o `.evtx` no parser na [página inicial deste site](/pt). O ficheiro é lido na memória do browser e parsado localmente por um Web Worker a correr o crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilado para WebAssembly. Nada sai da sua máquina. Confirme desligando-se da rede antes de largar o ficheiro.

Obtém a mesma vista ao nível do registo que uma ferramenta desktop produz: timeline filtrável, `<EventData>` completo achatado para a tabela, XML completo a um clique, exportação CSV/JSON do conjunto filtrado. Ideal para triagem ad-hoc quando não quer instalar nada, não quer fazer upload, ou está numa máquina que não é sua.

Restrição. Os limites de memória do browser fazem com que ficheiros maiores que cerca de 500 MB fiquem lentos. Para logs arquivados de múltiplos gigabytes, desça a uma ferramenta nativa.

## Método 2: Event Viewer, só Windows, integrado

Cada instalação de Windows traz o Event Viewer. Inicie `eventvwr.msc`, depois **Action / Open Saved Log** e escolha o `.evtx`. O Event Viewer oferece importar o ficheiro para a sua vista atual. Aceite e pode navegá-lo como qualquer canal ao vivo.

```text
Action -> Open Saved Log -> Browse -> selecionar .evtx -> OK
```

Bom para navegar num único ficheiro, olhar para a mensagem amigavelmente formatada de um registo, copiar e colar uma vista XML. Fraco para filtrar milhares de registos (a UI fica lenta), exportação em massa ou correr queries que quer programar. Também é o mais estrito quanto a chunks dirty à cauda: vai recusar ficheiros que outras ferramentas aceitam.

## Método 3: wevtutil e Get-WinEvent, linha de comandos do Windows

O `wevtutil` é o built-in do Windows para gestão de logs. O `Get-WinEvent` é o seu equivalente em PowerShell. Ambos funcionam em ficheiros `.evtx` guardados, não só em canais ao vivo.

Despejar cada registo de um `.evtx` guardado para texto:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrar com XPath. Cada 4624 nas últimas 24 horas:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell com a mesma intenção, mas a devolver objetos tipados:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Bom para extração programática, jobs agendados, filtragem cirúrgica. O compromisso é a verbosidade. XPath contra XML é preciso mas não é amigável.

## Método 4: EvtxECmd, o standard de DFIR

O [`EvtxECmd` de Eric Zimmerman](https://ericzimmerman.github.io/) é o parser para o qual a maioria dos praticantes de IR vai por defeito. Corre nativamente em Windows e em macOS / Linux via .NET. Faz parse mais rápido que o `wevtutil` e achata cada campo `<EventData>` numa coluna CSV. Uma linha por registo.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Para uma pasta `winevt\Logs\` inteira numa passagem, com maps que descodificam campos de eventos conhecidos em colunas amigáveis:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Ideal para parse em massa de coleções multi-ficheiro, importação para um SIEM ou notebook, workflow de analista multiplataforma. O EvtxECmd é a resposta certa para quase qualquer tarefa de "parsa isto offline". Combine-o com o target `EventLogs` do KAPE e tem uma missão de um comando.

## Método 5: python-evtx, programe num pipeline

Quando o ficheiro precisa de alimentar um pipeline Python, o [`python-evtx`](https://github.com/williballenthin/python-evtx) é o parser puro Python.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

Num notebook ou script:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Mais lento do que o crate Rust (Python interpretado em chunks binários), mas a escolha certa quando já está dentro de uma cadeia de ferramentas Python: notebooks forenses Jupyter, jobs de threat-hunting, enriquecimento personalizado, juntar dados EVTX a artefactos de [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com) ou [prefetch](https://www.prefetchparser.com) do mesmo caso.

## Que método usar quando

- Só quer olhar para o ficheiro: largue-o no [parser da página inicial](/pt). Mais rápido, zero instalação.
- Endpoint Windows com admin e o ficheiro é pequeno: Event Viewer.
- Extração one-off programática: `wevtutil` ou `Get-WinEvent`.
- DFIR real em coleções multi-canal: EvtxECmd.
- Construir um pipeline em Python: `python-evtx`.

## Erros comuns e como os ler

- "O ficheiro não parece ser válido" no Event Viewer significa quase sempre que o chunk à cauda está dirty (o ficheiro foi copiado enquanto o serviço EventLog ainda estava a escrever). A maioria dos parsers lida com isto. Tente o [parser do browser](/pt) ou o `EvtxECmd`, que ambos reportam chunks dirty como aviso e continuam.
- "Access is denied" do `wevtutil` contra um ficheiro em `winevt\Logs\` é o serviço EventLog a manter um lock exclusivo. Veja [recolher .evtx de um sistema ativo](/pt/blog/collecting-evtx-from-live-system) para as quatro formas padrão de contornar.
- Saída vazia do `Get-WinEvent` num log guardado. Passe o ficheiro com `-Path`, não `-LogName`. `-LogName` só lê canais ao vivo.
- PowerShell `Get-WinEvent` diz "No events were found that match the specified selection criteria". As chaves do seu `-FilterHashtable` são case-sensitive em algumas propriedades. Tente primeiro sem o filtro para confirmar que o ficheiro parse.

Para contexto sobre o que está realmente dentro de um `.evtx` e porque o formato é como é, veja [a análise ao nível dos chunks](/pt/blog/evtx-file-format-chunks).

## Leitura adicional

- [Ferramentas de Eric Zimmerman](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)
