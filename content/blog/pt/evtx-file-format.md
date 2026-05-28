---
title: "O formato de ficheiro EVTX, descodificado"
description: "Um tour prático pelo formato binário EVTX: cabeçalho de ficheiro, chunks ELFCHNK, templates BinXML, arrays de substituição e porque é que parsar isto é mais difícil do que parece."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

O antigo formato EVT era quase legível com um editor hex e paciência. O EVTX não é. A Microsoft substituiu-o no Vista por algo desenhado para throughput de escrita e consumo por máquina, e o efeito colateral é que toda a gente que quer ler um ficheiro EVTX acaba a reimplementar as mesmas algumas centenas de páginas das notas de engenharia reversa de Andreas Schuster. O formato está documentado em `[MS-EVEN6]` apenas ao nível do protocolo. A estrutura on-disk tem de a descobrir sozinho ou pedir emprestada ao `libevtx`.

Este post é a versão disto que eu gostaria de ter tido quando comecei.

## O cabeçalho de ficheiro, brevemente

Cada ficheiro EVTX abre com um cabeçalho de ficheiro de 4096 bytes. A magic é `ElfFile\0` no offset 0. A seguir, os campos com que realmente se importa durante triagem:

- `FirstChunkNumber` e `LastChunkNumber` — índices de chunk, não offsets em bytes.
- `NextRecordIdentifier` — o próximo RecordID que seria escrito. Útil para detetar truncamento.
- `HeaderSize` — quase sempre 128, com o resto dos 4096 bytes zero-padded.
- `MinorVersion` / `MajorVersion` — `3.1` é a versão que todo o Windows moderno escreve.
- `FileFlags` — bit 0 definido significa que o ficheiro está dirty (não foi fechado limpamente), bit 1 significa que esteve "full" e está a rodar. Ambos importam para interpretação forense.
- Um CRC32 sobre os primeiros 120 bytes do cabeçalho. Ferramentas que ignoram o CRC vão felizmente parsar cabeçalhos corrompidos; ferramentas que o forçam vão rejeitar ficheiros dos quais ainda consegue recuperar registos. Saiba qual é o seu caso.

Depois do cabeçalho, obtém uma sequência de chunks de 65.536 bytes. Sempre 64 KB, sempre alinhados. Esta é a unidade que o Windows escreve atomicamente, e é a unidade que recupera por carving.

## ELFCHNK: o cabeçalho de chunk

Cada chunk começa com `ElfChnk\0` na fronteira do chunk. O cabeçalho tem 512 bytes e carrega os campos que tornam o parsing possível:

- `FirstEventRecordNumber` e `LastEventRecordNumber` — o intervalo de RecordIDs coberto por este chunk.
- `FirstEventRecordIdentifier` e `LastEventRecordIdentifier` — a mesma coisa, mantido por legado.
- `FirstEventRecordOffset` — onde começam os bytes do primeiro registo dentro deste chunk.
- `LastEventRecordOffset` — onde começa o último registo. Se isto está depois do fim do chunk preenchido, o chunk foi escrito parcialmente; o escritor crashou.
- Uma `StringTable` e uma `TemplateTable`, ambas tabelas hash com chaves de hashes ao estilo FNV, a apontar para o payload BinXML do chunk.
- Dois CRCs: um sobre o cabeçalho, um sobre a área de registos.

As tabelas de strings e templates são a parte que faz tropeçar. Os templates e strings são guardados *uma vez por chunk* e referenciados por offset dentro do chunk. Isto significa que não consegue parsar um registo isoladamente de forma significativa. Precisa do chunk envolvente, com as suas tabelas resolvidas, para renderizar o XML do registo. Recupera um registo sem o seu chunk e obtém um array de substituição sem template para substituir.

`NumLogRecords` vive implicitamente como `LastEventRecordNumber - FirstEventRecordNumber + 1`. Alguma documentação inicial chamava este campo pelo nome; parsers modernos calculam-no.

## Codificação de EventRecord

Depois do cabeçalho do chunk obtém registos, encostados uns aos outros, até o chunk estar cheio ou o resto estar zerado. Cada registo começa com a magic `2a 2a 00 00` (o que torna carving por assinatura a partir de disco em bruto viável — mais sobre isto num post separado) seguida por:

- `Size` — comprimento total do registo incluindo a repetição final do size.
- `EventRecordIdentifier` — o RecordID monotonicamente crescente.
- `WriteTime` — um FILETIME do Windows, ticks de 100-ns desde 1601-01-01 UTC.
- O payload BinXML.
- `Size` outra vez, repetido na cauda para um leitor poder percorrer registos para trás.

O payload BinXML é onde o trabalho real começa.

## BinXML e o modelo template/substituição

BinXML é um stream de tokens que codifica XML como opcodes binários. Os opcodes que importam:

- `0x00` end-of-stream.
- `0x01` open start tag (com atributos).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, seguido por um `ValueType` e os bytes do valor.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` substituição normal.
- `0x0e` substituição condicional.
- `0x0f` start of stream (com preâmbulo de 3 bytes).

O escritor de event log do Windows quase nunca emite XML em bruto para um evento. Emite uma *template instance* (`0x0c`), que referencia uma definição de template (guardada uma vez por chunk por ID) e fornece um *array de substituição* contendo os valores variáveis para esse template. Para renderizar um único registo XML legível por humano precisa de:

1. Localizar o template na tabela de templates do chunk pelo seu template ID e offset.
2. Percorrer o BinXML do template, tratando-o como um esqueleto com placeholders de substituição numerados.
3. Para cada placeholder, procurar a entrada correspondente no array de substituição, fazer type-check contra o tipo declarado do placeholder, e inlining.

O array de substituição tem entradas tipadas: UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, mais strings em UTF-16LE inline ou por referência de offset, mais arrays de qualquer um destes. Tipo 0x21 é "BinXML" o que significa que a substituição é ela própria um stream BinXML aninhado, o que significa que os parsers precisam de recursão. É aqui que implementações ingénuas caem.

Duas armadilhas que vale a pena sinalizar:

- Templates podem ser referenciados a partir de *outros* registos no mesmo chunk por offset. Se construir um parser que só resolve templates quando vê a sua declaração inline, vai falhar registos que referenciam um template anterior só pelo ID.
- O tipo "conditional substitution" (`0x0e`) significa: substituir se o valor for não-nulo, caso contrário omitir o elemento pai. Saltar esta distinção produz XML que parece bem mas tem elementos vazios onde o log real não teria nada.

## Porque é isto mais difícil do que parsar EVT

EVT era um ficheiro flat de registos de forma fixa. Strings eram guardadas inline. Podia escrever um parser numa tarde.

EVTX é um formato paginado, otimizado para escrita, auto-deduplicador. A mesma string ("Microsoft-Windows-Security-Auditing") é guardada uma vez por chunk e referenciada por cada registo que a use. O mesmo esqueleto XML ("um evento 4624") é guardado uma vez por chunk como template, e cada registo 4624 nesse chunk é um array de substituição contra ele. Estado cross-registo importa. Estado cross-chunk não, o que é a saída de emergência: perde um chunk e perde os seus registos, mas o resto do ficheiro é recuperável.

Esta deduplicação é o que torna o EVTX pequeno o suficiente para manter em hosts movimentados e o que torna parsers ingénuos errados. Se alguma vez viu um EVTX "parsado" em que o campo `Provider` de cada registo diz "Unknown", viu um parser que não resolveu a tabela de strings.

## As ferramentas que realmente funcionam

- `python-evtx` (Willi Ballenthin) — lento, Python puro, mas a implementação de referência mais limpa. Leia o código antes de escrever o seu.
- `evtx_dump` do crate Rust `evtx` de Omer Ben-Amram — rápido, robusto, o default para dumping na linha de comandos. Saída JSONL que faz pipe para qualquer coisa.
- `libevtx` e `evtxtools` (Joachim Metz) — biblioteca C, a referência canónica do formato. Os bindings Python (`pyevtx`) são mais lentos do que `python-evtx` em alguns workloads mas lidam melhor com casos de borda.
- `EvtxECmd` de Eric Zimmerman — .NET, sem dúvida o melhor para trabalho de IR em campo devido ao seu sistema de maps. Maps são ficheiros YAML que achatam as substituições EventData em colunas nomeadas, que é o que se quer para grep e trabalho de timeline. Combine com o `Timeline Explorer`.
- O [parser neste site](https://www.evtxparser.com) — baseado em browser, útil quando não quer fazer upload de dados regulados para um fornecedor e não tem o seu kit na máquina onde está a trabalhar.

Se está a escrever um parser do zero (não, mas se tem de), o corpus de testes contra o qual validar são as amostras EVTX públicas do repo [SANS DFIR poster](https://github.com/forensicmatt/EVTX-ETW-Resources) e os sample logs do `hayabusa` da Yamato Security. Cobrem os casos de chunk malformado e registo parcial em que o seu código vai errar na primeira passagem.

A outra coisa que vale a pena dizer: o formato é partilhado com outros artefactos Windows. A mesma codificação FILETIME aparece no [registry](https://www.registryparser.com), nos timestamps `$STANDARD_INFORMATION` do [MFT](https://www.mftparser.com), nos cabeçalhos do [Prefetch](https://www.prefetchparser.com). Ficar bom a ler FILETIME de cabeça e muita forense Windows fica mais quieta.

## Leitura adicional

- O original ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) de Andreas Schuster (DFRWS 2007). O paper de engenharia reversa que tudo depois cita.
- A [especificação do formato libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc) de Joachim Metz. O mais próximo de uma referência completa.
- O [código fonte python-evtx](https://github.com/williballenthin/python-evtx) de Willi Ballenthin. Leia `Evtx/Nodes.py` para a hierarquia de nós BinXML.
- O [crate Rust evtx](https://github.com/omerbenamram/evtx) de Omer Ben-Amram. O caminho rápido sobre o qual a maioria das tooling modernas assenta.
