---
title: "Formato de arquivo EVTX explicado: chunks, templates e internals de BinXML"
description: "Como um arquivo .evtx é organizado em nível de byte — file header, chunks de 64 KB, a tabela de templates e o stream de registros BinXML que a referencia."
date: "2026-05-17"
---

O [formato Windows Event Log — `.evtx`](/pt/blog/what-is-an-evtx-file) — foi introduzido com o Windows Vista para substituir o `.evt` orientado a linha. É um container binário, append-only, em chunks, projetado para ser escrito por um único processo (o serviço EventLog) e rotacionado ou selado quando cheio. Entender como ele é organizado torna os casos de recuperação forense — arquivos parciais, dirty chunks, carving — muito mais fáceis.

## File header

Todo `.evtx` começa com um header de 4 KB (magic `ElfFile\0\0`, versão, contagem de chunks, índices oldest/current de chunk e um CRC32). O header é reescrito in-place toda vez que o arquivo é rotacionado ou um chunk é selado, o que torna seus flags `Dirty` e `Full` indicadores úteis: um arquivo com `Dirty` setado estava aberto quando o host crashou ou a imagem de disco foi adquirida ao vivo.

Após o header vem uma sequência de chunks de tamanho fixo.

## Chunks (64 KB)

Cada chunk tem exatamente 64 KB e seu próprio header de 512 bytes (magic `ElfChnk\0`, log record IDs do primeiro e último registro no chunk, offsets de arquivo, dois CRC32 — um para o header, um para os dados de registro). Chunks são independentes: você pode recuperar um chunk de espaço não alocado e parseá-lo sem o resto do arquivo. Isso é o que torna EVTX recuperável de fragmentos de disco.

Dentro de um chunk:

- **String table** — strings internadas dentro deste chunk, referenciadas por offset.
- **Template table** — templates XML usados por registros neste chunk, também indexados por offset.
- **Records** — um stream de registros BinXML, cada um referenciando um template mais valores de substituição por registro.

## BinXML e templates

Registros EVTX não são armazenados como texto XML. São armazenados como **BinXML**, uma representação binária tokenizada de um documento XML. Para economizar espaço, o esqueleto estrutural (nomes de elemento, nomes de atributo, a forma da árvore) é fatorado em um **template** armazenado uma vez na template table do chunk. Cada registro então diz "use template ID 5, com valores [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Para reconstruir o XML de um registro, um parser:

1. Lê o token stream do registro.
2. Procura o template pelo ID na template table do chunk.
3. Substitui os valores por registro nas posições de placeholder do template.
4. Emite o XML resultante.

É por isso que [parsers](/pt/blog/how-to-open-an-evtx-file) (incluindo o que powera esta página, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) precisam rastrear contexto chunk-local — IDs de template não são globais entre o arquivo.

## Chunks sealed vs dirty

Quando o serviço EventLog termina de escrever um chunk e move para o próximo, ele computa e escreve o CRC32 do chunk e marca o header do chunk como `Full`. Um arquivo limpo tem todo chunk nesse estado exceto o último.

Um chunk `Dirty` — last-modified time depois do header do arquivo ter sido atualizado pela última vez — é o tail ao vivo. Frequentemente é parseável, mas ferramentas às vezes se recusam a lê-lo porque o stream de registros pode terminar no meio de um token. Para forense isso importa: um atacante que adquiriu um host no meio da escrita verá um chunk final dirty, e o comportamento do seu parser nesse chunk precisa ser conhecido (ele pula, dá erro ou recupera o que pode?).

## Implicações práticas para parsing

- Um `.evtx` truncado — comum quando você [coleta de um host ativo](/pt/blog/collecting-evtx-from-live-system) — frequentemente ainda é mostly recuperável, porque todo chunk completo é independente.
- Chunks carved de não alocado podem ser embrulhados com um file header sintético e parseados.
- Um parse falho de um chunk não significa falha do arquivo — parsers robustos passam para o próximo chunk.
- O CRC32 do chunk é o que sinaliza tampering: um registro modificado que não recomputa o CRC é detectável.
