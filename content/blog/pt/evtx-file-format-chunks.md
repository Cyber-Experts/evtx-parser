---
title: "Formato do ficheiro EVTX explicado: chunks, templates e internals do BinXML"
description: "Como um ficheiro .evtx está organizado ao nível dos bytes: cabeçalho de ficheiro, chunks de 64 KB, a tabela de templates e o stream de registos BinXML que a referencia."
date: "2026-05-17"
---

O [formato Windows Event Log `.evtx`](/pt/blog/what-is-an-evtx-file) saiu com o Vista para substituir o `.evt` orientado a linhas. É um contentor binário, append-only, em chunks, escrito por um único processo (o serviço EventLog) e rodado quando cheio. A maioria dos analistas nunca precisa de saber como está organizado ao nível dos bytes. Os que recuperam registos por carving de espaço não alocado, que parsam manualmente chunks danificados ou que discutem com um parser que se recusa a ler um ficheiro truncado, precisam muito.

Este post é a versão prática. Internos suficientes para depurar um parse partido, não tanto que acabe por escrever o seu próprio parser do zero.

## Cabeçalho de ficheiro

Cada `.evtx` começa com um cabeçalho de 4 KB. A magic é `ElfFile\0\0`. Os campos que importam a um investigador são versão, contagem de chunks, índices do chunk mais antigo e atual, e um CRC32 sobre o próprio cabeçalho. O cabeçalho é reescrito in place sempre que o ficheiro roda ou um chunk é selado, por isso as suas flags `Dirty` e `Full` são pistas úteis. Um ficheiro com `Dirty` definido estava aberto quando o host crashou ou quando a imagem de disco foi adquirida ao vivo.

A seguir ao cabeçalho vem uma sequência de chunks de tamanho fixo.

## Chunks: 64 KB cada

Cada chunk tem exatamente 65.536 bytes e o seu próprio cabeçalho de 512 bytes. A magic do chunk é `ElfChnk\0`. O cabeçalho carrega os IDs de registo do primeiro e último registo no chunk, os offsets do ficheiro e dois CRC32: um sobre o cabeçalho, um sobre os dados de registo.

Os chunks são independentes. Pode recuperar um chunk de espaço não alocado e parsá-lo sem o resto do ficheiro. É isto que torna o EVTX [recuperável de fragmentos de disco](/pt/blog/carve-deleted-evtx-records), e é também o que torna o formato mais amigável a ferramentas forenses do que algo que comprime ao longo do ficheiro inteiro.

Dentro de um chunk:

- **Tabela de strings.** Strings internadas dentro deste chunk, referenciadas por offset.
- **Tabela de templates.** Templates XML usados por registos neste chunk, também indexados por offset.
- **Registos.** Um stream de registos BinXML, cada um a referenciar um template e valores de substituição por registo.

## BinXML e templates

Os registos EVTX não são armazenados como texto XML. São armazenados como **BinXML**, uma representação binária tokenizada de um documento XML. Para poupar espaço, o esqueleto estrutural (nomes de elementos, nomes de atributos, forma da árvore) é fatorizado num **template** armazenado uma vez na tabela de templates do chunk. Cada registo diz então "usar o template ID 5, com os valores [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Para reconstruir o XML de um registo, um parser:

1. Lê o stream de tokens do registo.
2. Procura o template por ID na tabela de templates do chunk.
3. Substitui os valores por registo nas posições de placeholder do template.
4. Emite o XML resultante.

É por isto que os parsers (o [parser de browser deste site](/pt/blog/how-to-open-an-evtx-file), o crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) que ele encapsula, e o python-evtx, todos partilham este requisito) precisam de manter contexto local ao chunk. Os IDs de template não são globais ao longo do ficheiro. Dois chunks podem ter tabelas de templates inteiramente diferentes; o mesmo número de template ID significa coisas diferentes em cada um.

É também a razão mais comum por que os analistas veem "XML lixo" quando tentam descodificar à mão um registo que tiraram com `xxd`. Sem a tabela de templates, os valores de substituição são apenas um saco de valores tipados sem esquema.

## Chunks selados vs dirty

Quando o serviço EventLog acaba de escrever um chunk e passa ao seguinte, calcula e escreve o CRC32 do chunk e marca o cabeçalho do chunk como `Full`. Um ficheiro limpo tem todos os chunks neste estado exceto o último.

Um chunk `Dirty` (hora da última modificação após a última atualização do cabeçalho do ficheiro) é a cauda ativa. Frequentemente é parsável, mas as ferramentas por vezes recusam-se a lê-lo porque o stream de registos pode terminar a meio de um token. Para forenses isto importa: um bundle [recolhido de um host ativo](/pt/blog/collecting-evtx-from-live-system) vai ter um chunk dirty à cauda no canal ativo, e o comportamento do seu parser nesse chunk tem de ser conhecido. Salta o chunk, dá erro no ficheiro ou recupera o que pode?

EvtxECmd, hayabusa e python-evtx todos recuperam chunks dirty com tolerância variável. O Event Viewer nativo é o mais estrito e recusa o ficheiro de todo mais vezes do que os outros.

## Implicações práticas

- Um `.evtx` truncado, comum quando se [recolhe de um host ativo](/pt/blog/collecting-evtx-from-live-system), é frequentemente quase totalmente recuperável. Cada chunk completo é independente.
- Chunks recuperados de espaço não alocado podem ser embrulhados num cabeçalho de ficheiro sintético e parsados. É assim que o libevtx e o python-evtx recuperam de varreduras de carving em `pagefile.sys` (ver [parser de pagefile](https://www.pagefilesysparser.com)) e [RAM dump](https://www.ramparser.com).
- Um parse falhado de um chunk não significa falha do ficheiro. Parsers robustos seguem para o próximo chunk e reportam o mau separadamente.
- O CRC32 do chunk é o que sinaliza adulteração. Um registo modificado que não recompute o CRC é detetável. A maioria dos atacantes não se incomoda porque limpar o log (disparando o [1102](/pt/blog/event-id-1102-cleared-log)) é o caminho mais fácil. Os cuidadosos usam o Phant0m, que deixa o ficheiro inteiramente em paz.

## Leitura adicional

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (trabalho original de engenharia reversa)
- [Documentação libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (a especificação de formato mais completa em circulação)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (parser Rust, o build WASM alimenta o parser de browser deste site)
