import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";

export const EVTX_TO_JSON: LocaleContent<LandingContent> = {
  en: {
    metaTitle: "EVTX to JSON Converter — free online, no upload",
    metaDescription:
      "Convert a Windows .evtx event log to JSON in your browser. Free EVTX to JSON converter — no upload, no install. Structured EventData plus raw XML, ready for jq or a SIEM.",
    h1: "Convert EVTX to JSON",
    intro:
      "Turn a Windows .evtx event log into structured JSON — ready for jq, Python, a notebook or a SIEM ingest pipeline — directly in your browser. The same Rust parser behind evtx_dump runs locally as WebAssembly, so the file never leaves your device.",
    ctaLabel: "Open the EVTX to JSON converter",
    formatsHeading: "What the JSON contains",
    formats: [
      {
        name: "One object per event",
        body: "The export is an array with one object per event: record_id, timestamp, level, event_id, provider, channel, computer, an event_data object holding every EventData field, and the full event xml.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Multi-file aware",
        body: "Load several .evtx files at once and each object gets a source_file field, so a combined export still tells you where each event came from.",
      },
      {
        name: "Filtered exports",
        body: "Only the rows that match your current filter are exported, which keeps a triage extract small enough to share or diff.",
      },
    ],
    stepsHeading: "How to convert EVTX to JSON",
    steps: [
      {
        title: "Open the converter",
        body: "Open the EVTX parser homepage. The WebAssembly parser loads in your tab; nothing is uploaded.",
      },
      {
        title: "Drop your .evtx file",
        body: "Drag one or more .evtx files onto the drop zone, or click to choose them.",
      },
      {
        title: "Filter, then Export JSON",
        body: "Narrow the events if you like, then click Export JSON. The .json file downloads locally.",
      },
    ],
    faqHeading: "EVTX to JSON FAQ",
    faq: [
      {
        q: "How do I convert EVTX to JSON from the command line?",
        a: "Use evtx_dump from the omerbenamram/evtx project: evtx_dump -o json Security.evtx > events.json, or -o jsonl for one event per line. This site runs the same parser in the browser when you don't want to install anything.",
      },
      {
        q: "How do I convert EVTX to JSON with PowerShell?",
        a: "On Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. EventData stays inside the Message text unless you parse each event's XML yourself.",
      },
      {
        q: "Can I load the JSON into a SIEM or Elastic?",
        a: "Yes. Each object is self-contained with timestamp, Event ID, channel and fields, which maps directly onto most ingest pipelines. For large collections, evtx_dump -o jsonl streams line-delimited JSON that bulk loaders accept.",
      },
      {
        q: "Is the conversion done on a server?",
        a: "No. Parsing and conversion happen in a Web Worker inside your browser. The .evtx file is never transmitted.",
      },
    ],
  },
  fr: {
    metaTitle: "EVTX en JSON — convertisseur gratuit en ligne",
    metaDescription:
      "Convertissez un journal d'événements Windows .evtx en JSON dans votre navigateur. Gratuit, sans envoi ni installation. EventData structuré et XML brut, prêt pour jq ou un SIEM.",
    h1: "Convertir EVTX en JSON",
    intro:
      "Transformez un journal d'événements Windows .evtx en JSON structuré — prêt pour jq, Python, un notebook ou un pipeline d'ingestion SIEM — directement dans votre navigateur. Le même analyseur Rust qui alimente evtx_dump s'exécute localement en WebAssembly : le fichier ne quitte jamais votre appareil.",
    ctaLabel: "Ouvrir le convertisseur EVTX vers JSON",
    formatsHeading: "Ce que contient le JSON",
    formats: [
      {
        name: "Un objet par événement",
        body: "L'export est un tableau avec un objet par événement : record_id, timestamp, level, event_id, provider, channel, computer, un objet event_data contenant tous les champs EventData, et le xml complet de l'événement.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Compatible multi-fichiers",
        body: "Chargez plusieurs fichiers .evtx à la fois et chaque objet reçoit un champ source_file, afin qu'un export combiné indique toujours d'où provient chaque événement.",
      },
      {
        name: "Exports filtrés",
        body: "Seules les lignes correspondant à votre filtre actuel sont exportées, ce qui garde un extrait de triage assez compact pour être partagé ou comparé (diff).",
      },
    ],
    stepsHeading: "Comment convertir EVTX en JSON",
    steps: [
      {
        title: "Ouvrir le convertisseur",
        body: "Ouvrez la page d'accueil d'EVTX parser. L'analyseur WebAssembly se charge dans votre onglet ; rien n'est envoyé.",
      },
      {
        title: "Déposez votre fichier .evtx",
        body: "Glissez un ou plusieurs fichiers .evtx dans la zone de dépôt, ou cliquez pour les choisir.",
      },
      {
        title: "Filtrez, puis cliquez sur Exporter JSON",
        body: "Affinez les événements si vous le souhaitez, puis cliquez sur Exporter JSON. Le fichier .json est téléchargé localement.",
      },
    ],
    faqHeading: "FAQ sur la conversion EVTX vers JSON",
    faq: [
      {
        q: "Comment convertir EVTX en JSON en ligne de commande ?",
        a: "Utilisez evtx_dump du projet omerbenamram/evtx : evtx_dump -o json Security.evtx > events.json, ou -o jsonl pour un événement par ligne. Ce site exécute le même analyseur dans le navigateur lorsque vous ne voulez rien installer.",
      },
      {
        q: "Comment convertir EVTX en JSON avec PowerShell ?",
        a: "Sous Windows : Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. EventData reste dans le texte de Message à moins que vous n'analysiez vous-même le XML de chaque événement.",
      },
      {
        q: "Puis-je charger le JSON dans un SIEM ou Elastic ?",
        a: "Oui. Chaque objet est autonome avec l'horodatage, l'Event ID, le canal et les champs, ce qui correspond directement à la plupart des pipelines d'ingestion. Pour de grandes collections, evtx_dump -o jsonl produit du JSON délimité par ligne accepté par les chargeurs en masse.",
      },
      {
        q: "La conversion se fait-elle sur un serveur ?",
        a: "Non. L'analyse et la conversion se déroulent dans un Web Worker à l'intérieur de votre navigateur. Le fichier .evtx n'est jamais transmis.",
      },
    ],
  },
  de: {
    metaTitle: "EVTX zu JSON Konverter — kostenlos, ohne Upload",
    metaDescription:
      "Wandeln Sie ein Windows-.evtx-Ereignisprotokoll im Browser in JSON um. Kostenloser EVTX-zu-JSON-Konverter — ohne Upload, ohne Installation. Strukturierte EventData plus rohes XML, bereit für jq oder ein SIEM.",
    h1: "EVTX in JSON umwandeln",
    intro:
      "Verwandeln Sie ein Windows-.evtx-Ereignisprotokoll direkt im Browser in strukturiertes JSON — bereit für jq, Python, ein Notebook oder eine SIEM-Ingest-Pipeline. Derselbe Rust-Parser, der evtx_dump antreibt, läuft lokal als WebAssembly, sodass die Datei Ihr Gerät nie verlässt.",
    ctaLabel: "EVTX-zu-JSON-Konverter öffnen",
    formatsHeading: "Was das JSON enthält",
    formats: [
      {
        name: "Ein Objekt pro Ereignis",
        body: "Der Export ist ein Array mit einem Objekt pro Ereignis: record_id, timestamp, level, event_id, provider, channel, computer, ein event_data-Objekt mit allen EventData-Feldern sowie das vollständige xml des Ereignisses.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Mehrdateifähig",
        body: "Laden Sie mehrere .evtx-Dateien gleichzeitig, und jedes Objekt erhält ein source_file-Feld, sodass ein kombinierter Export weiterhin zeigt, woher jedes Ereignis stammt.",
      },
      {
        name: "Gefilterte Exporte",
        body: "Es werden nur die Zeilen exportiert, die Ihrem aktuellen Filter entsprechen, sodass ein Triage-Auszug klein genug bleibt, um geteilt oder verglichen (diff) zu werden.",
      },
    ],
    stepsHeading: "So konvertieren Sie EVTX in JSON",
    steps: [
      {
        title: "Konverter öffnen",
        body: "Öffnen Sie die Startseite von EVTX parser. Der WebAssembly-Parser wird in Ihrem Tab geladen; es wird nichts hochgeladen.",
      },
      {
        title: "Legen Sie Ihre .evtx-Datei ab",
        body: "Ziehen Sie eine oder mehrere .evtx-Dateien in die Ablagezone, oder klicken Sie, um sie auszuwählen.",
      },
      {
        title: "Filtern und dann JSON exportieren klicken",
        body: "Grenzen Sie die Ereignisse bei Bedarf ein und klicken Sie dann auf JSON exportieren. Die .json-Datei wird lokal heruntergeladen.",
      },
    ],
    faqHeading: "FAQ zur EVTX-zu-JSON-Konvertierung",
    faq: [
      {
        q: "Wie konvertiere ich EVTX über die Kommandozeile in JSON?",
        a: "Verwenden Sie evtx_dump aus dem omerbenamram/evtx-Projekt: evtx_dump -o json Security.evtx > events.json, oder -o jsonl für ein Ereignis pro Zeile. Diese Website führt denselben Parser im Browser aus, wenn Sie nichts installieren möchten.",
      },
      {
        q: "Wie konvertiere ich EVTX mit PowerShell in JSON?",
        a: "Unter Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. EventData bleibt im Message-Text, sofern Sie nicht selbst das XML jedes Ereignisses parsen.",
      },
      {
        q: "Kann ich das JSON in ein SIEM oder Elastic laden?",
        a: "Ja. Jedes Objekt ist mit Zeitstempel, Event ID, Kanal und Feldern eigenständig, was direkt auf die meisten Ingest-Pipelines passt. Für große Sammlungen liefert evtx_dump -o jsonl zeilenweise getrenntes JSON, das Bulk-Loader akzeptieren.",
      },
      {
        q: "Erfolgt die Konvertierung auf einem Server?",
        a: "Nein. Parsen und Konvertierung erfolgen in einem Web Worker innerhalb Ihres Browsers. Die .evtx-Datei wird niemals übertragen.",
      },
    ],
  },
  es: {
    metaTitle: "Conversor de EVTX a JSON — gratis, sin subir archivos",
    metaDescription:
      "Convierte un registro de eventos de Windows .evtx a JSON en tu navegador. Conversor EVTX a JSON gratuito — sin subir nada, sin instalar. EventData estructurado y XML sin procesar, listo para jq o un SIEM.",
    h1: "Convertir EVTX a JSON",
    intro:
      "Convierte un registro de eventos de Windows .evtx en JSON estructurado — listo para jq, Python, un notebook o un pipeline de ingesta de SIEM — directamente en tu navegador. El mismo analizador Rust que impulsa evtx_dump se ejecuta localmente como WebAssembly, por lo que el archivo nunca sale de tu dispositivo.",
    ctaLabel: "Abrir el conversor de EVTX a JSON",
    formatsHeading: "Qué contiene el JSON",
    formats: [
      {
        name: "Un objeto por evento",
        body: "La exportación es un array con un objeto por evento: record_id, timestamp, level, event_id, provider, channel, computer, un objeto event_data con todos los campos EventData, y el xml completo del evento.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Compatible con varios archivos",
        body: "Carga varios archivos .evtx a la vez y cada objeto recibe un campo source_file, de modo que una exportación combinada siga indicando de dónde proviene cada evento.",
      },
      {
        name: "Exportaciones filtradas",
        body: "Solo se exportan las filas que coinciden con tu filtro actual, lo que mantiene un extracto de triaje lo bastante pequeño como para compartirlo o compararlo (diff).",
      },
    ],
    stepsHeading: "Cómo convertir EVTX a JSON",
    steps: [
      {
        title: "Abre el conversor",
        body: "Abre la página de inicio de EVTX parser. El analizador WebAssembly se carga en tu pestaña; no se sube nada.",
      },
      {
        title: "Suelta tu archivo .evtx",
        body: "Arrastra uno o varios archivos .evtx a la zona de soltar, o haz clic para elegirlos.",
      },
      {
        title: "Filtra y luego haz clic en Exportar JSON",
        body: "Acota los eventos si quieres y luego haz clic en Exportar JSON. El archivo .json se descarga localmente.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre la conversión de EVTX a JSON",
    faq: [
      {
        q: "¿Cómo convierto EVTX a JSON desde la línea de comandos?",
        a: "Usa evtx_dump del proyecto omerbenamram/evtx: evtx_dump -o json Security.evtx > events.json, o -o jsonl para un evento por línea. Este sitio ejecuta el mismo analizador en el navegador cuando no quieres instalar nada.",
      },
      {
        q: "¿Cómo convierto EVTX a JSON con PowerShell?",
        a: "En Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. EventData permanece dentro del texto de Message a menos que analices tú mismo el XML de cada evento.",
      },
      {
        q: "¿Puedo cargar el JSON en un SIEM o Elastic?",
        a: "Sí. Cada objeto es autónomo, con marca de tiempo, Event ID, canal y campos, lo que encaja directamente en la mayoría de los pipelines de ingesta. Para colecciones grandes, evtx_dump -o jsonl genera JSON delimitado por líneas que aceptan los cargadores masivos.",
      },
      {
        q: "¿La conversión se realiza en un servidor?",
        a: "No. El análisis y la conversión ocurren en un Web Worker dentro de tu navegador. El archivo .evtx nunca se transmite.",
      },
    ],
  },
  it: {
    metaTitle: "Convertitore EVTX in JSON — gratuito, senza upload",
    metaDescription:
      "Converti un registro eventi di Windows .evtx in JSON nel tuo browser. Convertitore EVTX in JSON gratuito — senza upload, senza installazione. EventData strutturato e XML grezzo, pronto per jq o un SIEM.",
    h1: "Convertire EVTX in JSON",
    intro:
      "Trasforma un registro eventi di Windows .evtx in JSON strutturato — pronto per jq, Python, un notebook o una pipeline di ingestione SIEM — direttamente nel tuo browser. Lo stesso parser Rust alla base di evtx_dump viene eseguito localmente come WebAssembly, quindi il file non lascia mai il tuo dispositivo.",
    ctaLabel: "Apri il convertitore EVTX in JSON",
    formatsHeading: "Cosa contiene il JSON",
    formats: [
      {
        name: "Un oggetto per evento",
        body: "L'esportazione è un array con un oggetto per evento: record_id, timestamp, level, event_id, provider, channel, computer, un oggetto event_data con tutti i campi EventData, e l'xml completo dell'evento.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Supporta più file",
        body: "Carica più file .evtx contemporaneamente e ogni oggetto riceve un campo source_file, così un'esportazione combinata indica comunque da dove proviene ciascun evento.",
      },
      {
        name: "Esportazioni filtrate",
        body: "Vengono esportate solo le righe che corrispondono al filtro attuale, il che mantiene un estratto di triage abbastanza piccolo da condividere o confrontare (diff).",
      },
    ],
    stepsHeading: "Come convertire EVTX in JSON",
    steps: [
      {
        title: "Apri il convertitore",
        body: "Apri la homepage di EVTX parser. Il parser WebAssembly si carica nella tua scheda; non viene caricato nulla.",
      },
      {
        title: "Rilascia il tuo file .evtx",
        body: "Trascina uno o più file .evtx nell'area di rilascio, oppure fai clic per sceglierli.",
      },
      {
        title: "Filtra, poi fai clic su Esporta JSON",
        body: "Restringi gli eventi se vuoi, poi fai clic su Esporta JSON. Il file .json viene scaricato localmente.",
      },
    ],
    faqHeading: "FAQ sulla conversione da EVTX a JSON",
    faq: [
      {
        q: "Come converto EVTX in JSON da riga di comando?",
        a: "Usa evtx_dump del progetto omerbenamram/evtx: evtx_dump -o json Security.evtx > events.json, oppure -o jsonl per un evento per riga. Questo sito esegue lo stesso parser nel browser quando non vuoi installare nulla.",
      },
      {
        q: "Come converto EVTX in JSON con PowerShell?",
        a: "Su Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. EventData resta all'interno del testo di Message a meno che tu non analizzi tu stesso l'XML di ciascun evento.",
      },
      {
        q: "Posso caricare il JSON in un SIEM o in Elastic?",
        a: "Sì. Ogni oggetto è autonomo, con timestamp, Event ID, canale e campi, il che si adatta direttamente alla maggior parte delle pipeline di ingestione. Per raccolte di grandi dimensioni, evtx_dump -o jsonl produce JSON delimitato da righe accettato dai bulk loader.",
      },
      {
        q: "La conversione avviene su un server?",
        a: "No. Il parsing e la conversione avvengono in un Web Worker all'interno del tuo browser. Il file .evtx non viene mai trasmesso.",
      },
    ],
  },
  pt: {
    metaTitle: "Conversor de EVTX para JSON — gratuito, sem upload",
    metaDescription:
      "Converta um log de eventos do Windows .evtx para JSON no seu navegador. Conversor EVTX para JSON gratuito — sem upload, sem instalação. EventData estruturado e XML bruto, pronto para jq ou um SIEM.",
    h1: "Converter EVTX para JSON",
    intro:
      "Transforme um log de eventos do Windows .evtx em JSON estruturado — pronto para jq, Python, um notebook ou um pipeline de ingestão de SIEM — diretamente no seu navegador. O mesmo parser Rust que alimenta o evtx_dump roda localmente como WebAssembly, de modo que o arquivo nunca sai do seu dispositivo.",
    ctaLabel: "Abrir o conversor de EVTX para JSON",
    formatsHeading: "O que o JSON contém",
    formats: [
      {
        name: "Um objeto por evento",
        body: "A exportação é um array com um objeto por evento: record_id, timestamp, level, event_id, provider, channel, computer, um objeto event_data com todos os campos EventData, e o xml completo do evento.",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "Compatível com vários arquivos",
        body: "Carregue vários arquivos .evtx de uma vez e cada objeto recebe um campo source_file, para que uma exportação combinada continue indicando de onde veio cada evento.",
      },
      {
        name: "Exportações filtradas",
        body: "Apenas as linhas que correspondem ao seu filtro atual são exportadas, o que mantém um extrato de triagem pequeno o suficiente para compartilhar ou comparar (diff).",
      },
    ],
    stepsHeading: "Como converter EVTX para JSON",
    steps: [
      {
        title: "Abra o conversor",
        body: "Abra a página inicial do EVTX parser. O parser WebAssembly é carregado na sua aba; nada é enviado.",
      },
      {
        title: "Solte seu arquivo .evtx",
        body: "Arraste um ou mais arquivos .evtx para a área de soltar, ou clique para escolhê-los.",
      },
      {
        title: "Filtre e depois clique em Exportar JSON",
        body: "Refine os eventos se quiser, depois clique em Exportar JSON. O arquivo .json é baixado localmente.",
      },
    ],
    faqHeading: "Perguntas frequentes sobre a conversão de EVTX para JSON",
    faq: [
      {
        q: "Como converto EVTX para JSON pela linha de comando?",
        a: "Use o evtx_dump do projeto omerbenamram/evtx: evtx_dump -o json Security.evtx > events.json, ou -o jsonl para um evento por linha. Este site executa o mesmo parser no navegador quando você não quer instalar nada.",
      },
      {
        q: "Como converto EVTX para JSON com PowerShell?",
        a: "No Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json. O EventData permanece dentro do texto de Message, a menos que você mesmo analise o XML de cada evento.",
      },
      {
        q: "Posso carregar o JSON em um SIEM ou no Elastic?",
        a: "Sim. Cada objeto é autocontido, com timestamp, Event ID, canal e campos, o que se encaixa diretamente na maioria dos pipelines de ingestão. Para coleções grandes, o evtx_dump -o jsonl gera JSON delimitado por linhas aceito por carregadores em massa (bulk loaders).",
      },
      {
        q: "A conversão é feita em um servidor?",
        a: "Não. A análise e a conversão acontecem em um Web Worker dentro do seu navegador. O arquivo .evtx nunca é transmitido.",
      },
    ],
  },
  ja: {
    metaTitle: "EVTX を JSON に変換 — 無料・アップロード不要",
    metaDescription:
      "Windows の .evtx イベントログをブラウザで JSON に変換。無料の EVTX to JSON コンバーター — アップロード不要、インストール不要。構造化された EventData と生 XML を、jq や SIEM にそのまま利用できます。",
    h1: "EVTX を JSON に変換",
    intro:
      "Windows の .evtx イベントログを、ブラウザ上で直接、構造化された JSON に変換します — jq、Python、ノートブック、SIEM の取り込みパイプラインにすぐ使えます。evtx_dump と同じ Rust パーサーが WebAssembly としてローカルで動作するため、ファイルがデバイスから出ることはありません。",
    ctaLabel: "EVTX to JSON コンバーターを開く",
    formatsHeading: "JSON に含まれる内容",
    formats: [
      {
        name: "イベントごとに 1 つのオブジェクト",
        body: "エクスポートはイベントごとに 1 つのオブジェクトを持つ配列です: record_id、timestamp、level、event_id、provider、channel、computer、すべての EventData フィールドを保持する event_data オブジェクト、そしてイベントの完全な xml。",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "複数ファイルに対応",
        body: "複数の .evtx ファイルを一度に読み込むと、各オブジェクトに source_file フィールドが付与されるため、結合したエクスポートでも各イベントの出所が分かります。",
      },
      {
        name: "フィルター済みエクスポート",
        body: "現在のフィルターに一致する行のみがエクスポートされるため、トリアージ用の抽出データを共有や diff に十分小さく保てます。",
      },
    ],
    stepsHeading: "EVTX を JSON に変換する方法",
    steps: [
      {
        title: "コンバーターを開く",
        body: "EVTX parser のホームページを開きます。WebAssembly パーサーがタブ内に読み込まれます。何もアップロードされません。",
      },
      {
        title: ".evtx ファイルをドロップする",
        body: "1 つまたは複数の .evtx ファイルをドロップゾーンにドラッグするか、クリックして選択します。",
      },
      {
        title: "絞り込んでから JSON をエクスポートをクリック",
        body: "必要に応じてイベントを絞り込み、JSON をエクスポートをクリックします。.json ファイルがローカルにダウンロードされます。",
      },
    ],
    faqHeading: "EVTX から JSON への変換に関する FAQ",
    faq: [
      {
        q: "コマンドラインで EVTX を JSON に変換するには？",
        a: "omerbenamram/evtx プロジェクトの evtx_dump を使用します: evtx_dump -o json Security.evtx > events.json、1 行 1 イベントにするには -o jsonl を使います。何もインストールしたくない場合、このサイトはブラウザ内で同じパーサーを実行します。",
      },
      {
        q: "PowerShell で EVTX を JSON に変換するには？",
        a: "Windows では: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json。自分で各イベントの XML を解析しない限り、EventData は Message テキストの中に残ります。",
      },
      {
        q: "JSON を SIEM や Elastic に読み込めますか？",
        a: "はい。各オブジェクトはタイムスタンプ、Event ID、チャネル、フィールドを含む自己完結型で、ほとんどの取り込みパイプラインに直接マッピングできます。大規模なコレクションでは、evtx_dump -o jsonl が一括ローダーが受け付ける行区切り JSON をストリーミングします。",
      },
      {
        q: "変換はサーバー上で行われますか？",
        a: "いいえ。解析と変換はブラウザ内の Web Worker で行われます。.evtx ファイルが送信されることはありません。",
      },
    ],
  },
  zh: {
    metaTitle: "EVTX 转 JSON 转换器——免费在线，无需上传",
    metaDescription:
      "在浏览器中将 Windows .evtx 事件日志转换为 JSON。免费的 EVTX 转 JSON 转换器——无需上传，无需安装。结构化的 EventData 加原始 XML，可直接用于 jq 或 SIEM。",
    h1: "将 EVTX 转换为 JSON",
    intro:
      "直接在浏览器中将 Windows .evtx 事件日志转换为结构化 JSON——可直接用于 jq、Python、notebook 或 SIEM 摄取流水线。支持 evtx_dump 的同一个 Rust 解析器以 WebAssembly 形式在本地运行，因此文件绝不会离开您的设备。",
    ctaLabel: "打开 EVTX 转 JSON 转换器",
    formatsHeading: "JSON 包含的内容",
    formats: [
      {
        name: "每个事件一个对象",
        body: "导出结果是一个数组，每个事件对应一个对象：record_id、timestamp、level、event_id、provider、channel、computer，一个包含所有 EventData 字段的 event_data 对象，以及事件的完整 xml。",
        code: '{\n  "record_id": 48213,\n  "timestamp": "2026-09-12T08:14:03.512Z",\n  "event_id": 4624,\n  "channel": "Security",\n  "event_data": { "LogonType": "10", "TargetUserName": "j.doe" },\n  "xml": "<Event xmlns=…>…</Event>"\n}',
      },
      {
        name: "支持多文件",
        body: "一次加载多个 .evtx 文件，每个对象都会获得一个 source_file 字段，因此合并导出仍能告诉您每个事件的来源。",
      },
      {
        name: "筛选后导出",
        body: "只会导出与当前筛选条件匹配的行，这样可以让分诊提取内容保持足够小，便于分享或比对（diff）。",
      },
    ],
    stepsHeading: "如何将 EVTX 转换为 JSON",
    steps: [
      {
        title: "打开转换器",
        body: "打开 EVTX parser 主页。WebAssembly 解析器会在您的标签页中加载；不会上传任何内容。",
      },
      {
        title: "拖入您的 .evtx 文件",
        body: "将一个或多个 .evtx 文件拖到拖放区，或单击选择它们。",
      },
      {
        title: "筛选后点击导出 JSON",
        body: "如有需要可先缩小事件范围，然后点击导出 JSON。.json 文件将下载到本地。",
      },
    ],
    faqHeading: "EVTX 转 JSON 常见问题",
    faq: [
      {
        q: "如何通过命令行将 EVTX 转换为 JSON？",
        a: "使用 omerbenamram/evtx 项目中的 evtx_dump：evtx_dump -o json Security.evtx > events.json，或使用 -o jsonl 实现每行一个事件。当您不想安装任何东西时，本网站会在浏览器中运行相同的解析器。",
      },
      {
        q: "如何使用 PowerShell 将 EVTX 转换为 JSON？",
        a: "在 Windows 上：Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json | Out-File events.json。除非您自行解析每个事件的 XML，否则 EventData 会保留在 Message 文本内。",
      },
      {
        q: "我可以将 JSON 加载到 SIEM 或 Elastic 中吗？",
        a: "可以。每个对象都是独立完整的，包含时间戳、Event ID、通道和字段，可直接映射到大多数摄取流水线。对于大型数据集，evtx_dump -o jsonl 会流式输出以换行分隔的 JSON，批量加载器可以直接接受。",
      },
      {
        q: "转换是在服务器上完成的吗？",
        a: "不是。解析和转换都在您浏览器内的 Web Worker 中进行。.evtx 文件绝不会被传输。",
      },
    ],
  },
};
