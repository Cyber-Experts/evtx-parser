import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";

export const EVTX_TO_CSV: LocaleContent<LandingContent> = {
  en: {
    metaTitle: "EVTX to CSV Converter — free online, no upload",
    metaDescription:
      "Convert a Windows .evtx event log to CSV in your browser and open it in Excel. Free EVTX to CSV converter — no upload, no install. EventData fields become real columns.",
    h1: "Convert EVTX to CSV",
    intro:
      "Turn a Windows .evtx event log into a CSV you can open in Excel, LibreOffice or pandas — directly in your browser. The file is parsed locally by a Rust parser compiled to WebAssembly, so nothing is uploaded and no Windows host is needed.",
    ctaLabel: "Open the EVTX to CSV converter",
    formatsHeading: "What the CSV contains",
    formats: [
      {
        name: "One row per event",
        body: "Every record becomes a row with the common columns: record number, timestamp (UTC), level, Event ID, provider, channel and computer. When you load several .evtx files at once, a Source column tells you which file each row came from.",
      },
      {
        name: "EventData as real columns",
        body: "Each EventData field (TargetUserName, LogonType, IpAddress, CommandLine…) gets its own column. Filter to a single Event ID first — 4624, 4688, Sysmon 1 — and you get a clean, analysis-ready table instead of a Message blob.",
      },
      {
        name: "Optional raw XML column",
        body: "Tick “Raw XML column” before exporting to add each event's full <Event> XML as the last column, for when you need a field the table does not show.",
      },
      {
        name: "Excel-friendly encoding",
        body: "The CSV is UTF-8 with a byte-order mark, so Excel opens accented user names, non-Latin paths and PowerShell script text without mangling them.",
      },
    ],
    stepsHeading: "How to convert EVTX to CSV",
    steps: [
      {
        title: "Open the converter",
        body: "Open the EVTX parser homepage. The WebAssembly parser loads in your tab; nothing is sent to a server.",
      },
      {
        title: "Drop your .evtx file",
        body: "Drag Security.evtx, System.evtx, a Sysmon or PowerShell log onto the drop zone, or click to pick one. Several files can be loaded together.",
      },
      {
        title: "Filter, then Export CSV",
        body: "Narrow the rows with the filter bar, the Event ID chips or the timeline, then click Export CSV. Only the filtered rows are written, and the file downloads locally.",
      },
    ],
    faqHeading: "EVTX to CSV FAQ",
    faq: [
      {
        q: "How do I convert EVTX to CSV with PowerShell?",
        a: "On Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. It needs a Windows host and puts all event fields into the single Message column; the in-browser converter splits EventData into separate columns and runs on any OS.",
      },
      {
        q: "Can Event Viewer save an EVTX file as CSV?",
        a: "Yes: open the log, choose Save All Events As… and pick CSV (Comma Separated). The output keeps only the summary columns plus the rendered message text, so you lose the structured EventData fields.",
      },
      {
        q: "How do I convert EVTX to CSV on Linux or macOS?",
        a: "Use this browser-based converter, or a command-line tool such as EvtxECmd (--csv) or evtx_dump piped through a JSON-to-CSV step. All of them parse the binary format directly, without Windows.",
      },
      {
        q: "Is my EVTX file uploaded during conversion?",
        a: "No. The file is read into your browser's memory and converted there. You can disconnect from the network after the page loads and the conversion still works.",
      },
    ],
  },
  fr: {
    metaTitle: "Convertisseur EVTX en CSV — gratuit, sans envoi",
    metaDescription:
      "Convertissez un journal d'événements Windows .evtx en CSV dans votre navigateur et ouvrez-le dans Excel. Convertisseur EVTX vers CSV gratuit — sans envoi, sans installation. Les champs EventData deviennent de vraies colonnes.",
    h1: "Convertir EVTX en CSV",
    intro:
      "Transformez un journal d'événements Windows .evtx en CSV que vous pouvez ouvrir dans Excel, LibreOffice ou pandas — directement dans votre navigateur. Le fichier est analysé localement par un analyseur Rust compilé en WebAssembly, donc rien n'est envoyé et aucune machine Windows n'est nécessaire.",
    ctaLabel: "Ouvrir le convertisseur EVTX vers CSV",
    formatsHeading: "Ce que contient le CSV",
    formats: [
      {
        name: "Une ligne par événement",
        body: "Chaque enregistrement devient une ligne avec les colonnes courantes : numéro d'enregistrement, horodatage (UTC), niveau, Event ID, fournisseur, canal et ordinateur. Lorsque vous chargez plusieurs fichiers .evtx à la fois, une colonne Source indique de quel fichier provient chaque ligne.",
      },
      {
        name: "EventData en vraies colonnes",
        body: "Chaque champ EventData (TargetUserName, LogonType, IpAddress, CommandLine…) obtient sa propre colonne. Filtrez d'abord sur un seul Event ID — 4624, 4688, Sysmon 1 — et vous obtenez un tableau propre, prêt à l'analyse, au lieu d'un bloc Message.",
      },
      {
        name: "Colonne XML brut en option",
        body: "Cochez “Colonne XML brut” avant l'export pour ajouter le XML <Event> complet de chaque événement en dernière colonne, pour les cas où vous avez besoin d'un champ que le tableau n'affiche pas.",
      },
      {
        name: "Encodage compatible Excel",
        body: "Le CSV est en UTF-8 avec une marque d'ordre des octets (BOM), afin qu'Excel ouvre correctement les noms d'utilisateur accentués, les chemins non latins et le texte de script PowerShell sans les corrompre.",
      },
    ],
    stepsHeading: "Comment convertir EVTX en CSV",
    steps: [
      {
        title: "Ouvrir le convertisseur",
        body: "Ouvrez la page d'accueil d'EVTX parser. L'analyseur WebAssembly se charge dans votre onglet ; rien n'est envoyé à un serveur.",
      },
      {
        title: "Déposez votre fichier .evtx",
        body: "Glissez Security.evtx, System.evtx, un journal Sysmon ou PowerShell dans la zone de dépôt, ou cliquez pour en choisir un. Plusieurs fichiers peuvent être chargés ensemble.",
      },
      {
        title: "Filtrez, puis Exporter CSV",
        body: "Affinez les lignes avec la barre de filtre, les puces Event ID ou la chronologie, puis cliquez sur “Exporter CSV”. Seules les lignes filtrées sont écrites, et le fichier est téléchargé localement.",
      },
    ],
    faqHeading: "FAQ sur la conversion EVTX vers CSV",
    faq: [
      {
        q: "Comment convertir EVTX en CSV avec PowerShell ?",
        a: "Sous Windows : Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. Cela nécessite une machine Windows et place tous les champs de l'événement dans la seule colonne Message ; le convertisseur dans le navigateur sépare EventData en colonnes distinctes et fonctionne sur n'importe quel système d'exploitation.",
      },
      {
        q: "Event Viewer peut-il enregistrer un fichier EVTX en CSV ?",
        a: "Oui : ouvrez le journal, choisissez “Save All Events As…” puis sélectionnez CSV (Comma Separated). Le résultat ne conserve que les colonnes de résumé et le texte du message généré, vous perdez donc les champs EventData structurés.",
      },
      {
        q: "Comment convertir EVTX en CSV sous Linux ou macOS ?",
        a: "Utilisez ce convertisseur dans le navigateur, ou un outil en ligne de commande comme EvtxECmd (--csv) ou evtx_dump associé à une étape JSON vers CSV. Tous analysent directement le format binaire, sans Windows.",
      },
      {
        q: "Mon fichier EVTX est-il envoyé pendant la conversion ?",
        a: "Non. Le fichier est lu dans la mémoire de votre navigateur et converti là. Vous pouvez vous déconnecter du réseau après le chargement de la page, la conversion fonctionne toujours.",
      },
    ],
  },
  de: {
    metaTitle: "EVTX-zu-CSV-Konverter — kostenlos, ohne Upload",
    metaDescription:
      "Wandeln Sie ein Windows-.evtx-Ereignisprotokoll im Browser in CSV um und öffnen Sie es in Excel. Kostenloser EVTX-zu-CSV-Konverter — ohne Upload, ohne Installation. EventData-Felder werden zu echten Spalten.",
    h1: "EVTX in CSV umwandeln",
    intro:
      "Verwandeln Sie ein Windows-.evtx-Ereignisprotokoll direkt im Browser in eine CSV-Datei, die Sie in Excel, LibreOffice oder pandas öffnen können. Die Datei wird lokal von einem in WebAssembly kompilierten Rust-Parser analysiert, sodass nichts hochgeladen wird und kein Windows-Host benötigt wird.",
    ctaLabel: "EVTX-zu-CSV-Konverter öffnen",
    formatsHeading: "Was die CSV enthält",
    formats: [
      {
        name: "Eine Zeile pro Ereignis",
        body: "Jeder Datensatz wird zu einer Zeile mit den gängigen Spalten: Datensatznummer, Zeitstempel (UTC), Stufe, Event ID, Anbieter, Kanal und Computer. Wenn Sie mehrere .evtx-Dateien gleichzeitig laden, zeigt eine Source-Spalte an, aus welcher Datei jede Zeile stammt.",
      },
      {
        name: "EventData als echte Spalten",
        body: "Jedes EventData-Feld (TargetUserName, LogonType, IpAddress, CommandLine…) erhält seine eigene Spalte. Filtern Sie zuerst auf eine einzelne Event ID — 4624, 4688, Sysmon 1 — und Sie erhalten eine saubere, analysebereite Tabelle statt eines Message-Blobs.",
      },
      {
        name: "Optionale Roh-XML-Spalte",
        body: "Aktivieren Sie „Rohe-XML-Spalte“ vor dem Export, um das vollständige <Event>-XML jedes Ereignisses als letzte Spalte hinzuzufügen — für Fälle, in denen Sie ein Feld benötigen, das die Tabelle nicht zeigt.",
      },
      {
        name: "Excel-freundliche Kodierung",
        body: "Die CSV ist UTF-8 mit Byte-Order-Mark, sodass Excel akzentuierte Benutzernamen, nicht-lateinische Pfade und PowerShell-Skripttext öffnet, ohne sie zu verstümmeln.",
      },
    ],
    stepsHeading: "So konvertieren Sie EVTX in CSV",
    steps: [
      {
        title: "Konverter öffnen",
        body: "Öffnen Sie die Startseite von EVTX parser. Der WebAssembly-Parser lädt in Ihrem Tab; es wird nichts an einen Server gesendet.",
      },
      {
        title: "Legen Sie Ihre .evtx-Datei ab",
        body: "Ziehen Sie Security.evtx, System.evtx, ein Sysmon- oder PowerShell-Protokoll in die Ablagezone, oder klicken Sie, um eines auszuwählen. Mehrere Dateien können zusammen geladen werden.",
      },
      {
        title: "Filtern, dann CSV exportieren",
        body: "Grenzen Sie die Zeilen mit der Filterleiste, den Event-ID-Chips oder der Zeitleiste ein, und klicken Sie dann auf „CSV exportieren“. Nur die gefilterten Zeilen werden geschrieben, und die Datei wird lokal heruntergeladen.",
      },
    ],
    faqHeading: "FAQ zur EVTX-zu-CSV-Konvertierung",
    faq: [
      {
        q: "Wie konvertiere ich EVTX mit PowerShell in CSV?",
        a: "Unter Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. Es benötigt einen Windows-Host und packt alle Ereignisfelder in die einzelne Message-Spalte; der Browser-Konverter trennt EventData in eigene Spalten und läuft auf jedem Betriebssystem.",
      },
      {
        q: "Kann Event Viewer eine EVTX-Datei als CSV speichern?",
        a: "Ja: Öffnen Sie das Protokoll, wählen Sie „Save All Events As…“ und dann CSV (Comma Separated). Die Ausgabe enthält nur die Übersichtsspalten plus den gerenderten Nachrichtentext, sodass die strukturierten EventData-Felder verloren gehen.",
      },
      {
        q: "Wie konvertiere ich EVTX unter Linux oder macOS in CSV?",
        a: "Verwenden Sie diesen browserbasierten Konverter oder ein Kommandozeilen-Tool wie EvtxECmd (--csv) oder evtx_dump in Kombination mit einem JSON-zu-CSV-Schritt. Alle analysieren das Binärformat direkt, ohne Windows.",
      },
      {
        q: "Wird meine EVTX-Datei bei der Konvertierung hochgeladen?",
        a: "Nein. Die Datei wird in den Speicher Ihres Browsers eingelesen und dort konvertiert. Sie können die Netzwerkverbindung nach dem Laden der Seite trennen, die Konvertierung funktioniert weiterhin.",
      },
    ],
  },
  es: {
    metaTitle: "Conversor de EVTX a CSV — gratis, sin subir",
    metaDescription:
      "Convierte un registro de eventos de Windows .evtx a CSV en tu navegador y ábrelo en Excel. Conversor EVTX a CSV gratuito — sin subir nada, sin instalar. Los campos EventData se convierten en columnas reales.",
    h1: "Convertir EVTX a CSV",
    intro:
      "Convierte un registro de eventos de Windows .evtx en un CSV que puedes abrir en Excel, LibreOffice o pandas — directamente en tu navegador. El archivo se analiza localmente con un analizador Rust compilado a WebAssembly, así que no se sube nada y no necesitas un host Windows.",
    ctaLabel: "Abrir el conversor de EVTX a CSV",
    formatsHeading: "Qué contiene el CSV",
    formats: [
      {
        name: "Una fila por evento",
        body: "Cada registro se convierte en una fila con las columnas habituales: número de registro, marca de tiempo (UTC), nivel, Event ID, proveedor, canal y equipo. Cuando cargas varios archivos .evtx a la vez, una columna Source indica de qué archivo proviene cada fila.",
      },
      {
        name: "EventData como columnas reales",
        body: "Cada campo EventData (TargetUserName, LogonType, IpAddress, CommandLine…) obtiene su propia columna. Filtra primero por un único Event ID — 4624, 4688, Sysmon 1 — y obtendrás una tabla limpia, lista para analizar, en lugar de un bloque Message.",
      },
      {
        name: "Columna XML sin procesar opcional",
        body: "Marca “Columna XML sin procesar” antes de exportar para añadir el XML <Event> completo de cada evento como última columna, para cuando necesites un campo que la tabla no muestra.",
      },
      {
        name: "Codificación compatible con Excel",
        body: "El CSV está en UTF-8 con marca de orden de bytes (BOM), de modo que Excel abre nombres de usuario con acentos, rutas no latinas y texto de scripts de PowerShell sin corromperlos.",
      },
    ],
    stepsHeading: "Cómo convertir EVTX a CSV",
    steps: [
      {
        title: "Abre el conversor",
        body: "Abre la página de inicio de EVTX parser. El analizador WebAssembly se carga en tu pestaña; no se envía nada a ningún servidor.",
      },
      {
        title: "Suelta tu archivo .evtx",
        body: "Arrastra Security.evtx, System.evtx, un registro de Sysmon o PowerShell a la zona de soltar, o haz clic para elegir uno. Puedes cargar varios archivos juntos.",
      },
      {
        title: "Filtra y luego Exportar CSV",
        body: "Reduce las filas con la barra de filtro, las etiquetas de Event ID o la línea de tiempo, y luego haz clic en “Exportar CSV”. Solo se escriben las filas filtradas, y el archivo se descarga localmente.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre EVTX a CSV",
    faq: [
      {
        q: "¿Cómo convierto EVTX a CSV con PowerShell?",
        a: "En Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. Necesita un host Windows y coloca todos los campos del evento en la única columna Message; el conversor en el navegador separa EventData en columnas distintas y funciona en cualquier sistema operativo.",
      },
      {
        q: "¿Puede Event Viewer guardar un archivo EVTX como CSV?",
        a: "Sí: abre el registro, elige “Save All Events As…” y selecciona CSV (Comma Separated). El resultado conserva solo las columnas de resumen más el texto del mensaje renderizado, por lo que pierdes los campos EventData estructurados.",
      },
      {
        q: "¿Cómo convierto EVTX a CSV en Linux o macOS?",
        a: "Usa este conversor en el navegador, o una herramienta de línea de comandos como EvtxECmd (--csv) o evtx_dump combinado con un paso de JSON a CSV. Todas analizan el formato binario directamente, sin Windows.",
      },
      {
        q: "¿Se sube mi archivo EVTX durante la conversión?",
        a: "No. El archivo se lee en la memoria de tu navegador y se convierte ahí. Puedes desconectarte de la red después de cargar la página y la conversión sigue funcionando.",
      },
    ],
  },
  it: {
    metaTitle: "Convertitore da EVTX a CSV — gratis, senza upload",
    metaDescription:
      "Converti un registro eventi di Windows .evtx in CSV nel tuo browser e aprilo in Excel. Convertitore EVTX in CSV gratuito — senza upload, senza installazione. I campi EventData diventano colonne reali.",
    h1: "Convertire EVTX in CSV",
    intro:
      "Trasforma un registro eventi di Windows .evtx in un CSV che puoi aprire in Excel, LibreOffice o pandas — direttamente nel tuo browser. Il file viene analizzato localmente da un parser Rust compilato in WebAssembly, quindi non viene caricato nulla e non serve un host Windows.",
    ctaLabel: "Apri il convertitore da EVTX a CSV",
    formatsHeading: "Cosa contiene il CSV",
    formats: [
      {
        name: "Una riga per evento",
        body: "Ogni record diventa una riga con le colonne comuni: numero di record, timestamp (UTC), livello, Event ID, provider, canale e computer. Quando carichi più file .evtx contemporaneamente, una colonna Source indica da quale file proviene ciascuna riga.",
      },
      {
        name: "EventData come colonne reali",
        body: "Ogni campo EventData (TargetUserName, LogonType, IpAddress, CommandLine…) ottiene la propria colonna. Filtra prima su un singolo Event ID — 4624, 4688, Sysmon 1 — e otterrai una tabella pulita, pronta per l'analisi, invece di un blob Message.",
      },
      {
        name: "Colonna XML grezzo opzionale",
        body: "Seleziona “Colonna XML grezzo” prima di esportare per aggiungere l'XML <Event> completo di ogni evento come ultima colonna, per quando ti serve un campo che la tabella non mostra.",
      },
      {
        name: "Codifica compatibile con Excel",
        body: "Il CSV è in UTF-8 con byte-order mark, così Excel apre nomi utente accentati, percorsi non latini e testo di script PowerShell senza corromperli.",
      },
    ],
    stepsHeading: "Come convertire EVTX in CSV",
    steps: [
      {
        title: "Apri il convertitore",
        body: "Apri la homepage di EVTX parser. Il parser WebAssembly si carica nella tua scheda; non viene inviato nulla a un server.",
      },
      {
        title: "Rilascia il tuo file .evtx",
        body: "Trascina Security.evtx, System.evtx, un log di Sysmon o PowerShell nell'area di rilascio, oppure fai clic per sceglierne uno. Puoi caricare più file insieme.",
      },
      {
        title: "Filtra, poi Esporta CSV",
        body: "Restringi le righe con la barra dei filtri, i chip Event ID o la timeline, poi fai clic su “Esporta CSV”. Vengono scritte solo le righe filtrate, e il file viene scaricato localmente.",
      },
    ],
    faqHeading: "FAQ su EVTX in CSV",
    faq: [
      {
        q: "Come converto EVTX in CSV con PowerShell?",
        a: "Su Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. Richiede un host Windows e inserisce tutti i campi dell'evento nell'unica colonna Message; il convertitore nel browser separa EventData in colonne distinte e funziona su qualsiasi sistema operativo.",
      },
      {
        q: "Event Viewer può salvare un file EVTX come CSV?",
        a: "Sì: apri il registro, scegli “Save All Events As…” e seleziona CSV (Comma Separated). Il risultato conserva solo le colonne di riepilogo più il testo del messaggio renderizzato, quindi perdi i campi EventData strutturati.",
      },
      {
        q: "Come converto EVTX in CSV su Linux o macOS?",
        a: "Usa questo convertitore nel browser, oppure uno strumento da riga di comando come EvtxECmd (--csv) o evtx_dump abbinato a un passaggio da JSON a CSV. Tutti analizzano direttamente il formato binario, senza Windows.",
      },
      {
        q: "Il mio file EVTX viene caricato durante la conversione?",
        a: "No. Il file viene letto nella memoria del tuo browser e convertito lì. Puoi disconnetterti dalla rete dopo il caricamento della pagina e la conversione continua a funzionare.",
      },
    ],
  },
  pt: {
    metaTitle: "Conversor de EVTX para CSV — grátis, sem upload",
    metaDescription:
      "Converta um log de eventos do Windows .evtx para CSV no seu navegador e abra-o no Excel. Conversor EVTX para CSV gratuito — sem upload, sem instalação. Os campos EventData tornam-se colunas reais.",
    h1: "Converter EVTX para CSV",
    intro:
      "Transforme um log de eventos do Windows .evtx em um CSV que você pode abrir no Excel, LibreOffice ou pandas — diretamente no seu navegador. O arquivo é analisado localmente por um parser Rust compilado para WebAssembly, então nada é enviado e nenhum host Windows é necessário.",
    ctaLabel: "Abrir o conversor de EVTX para CSV",
    formatsHeading: "O que o CSV contém",
    formats: [
      {
        name: "Uma linha por evento",
        body: "Cada registro vira uma linha com as colunas comuns: número do registro, carimbo de data/hora (UTC), nível, Event ID, provedor, canal e computador. Quando você carrega vários arquivos .evtx de uma vez, uma coluna Source indica de qual arquivo cada linha veio.",
      },
      {
        name: "EventData como colunas reais",
        body: "Cada campo EventData (TargetUserName, LogonType, IpAddress, CommandLine…) recebe sua própria coluna. Filtre primeiro por um único Event ID — 4624, 4688, Sysmon 1 — e você obtém uma tabela limpa, pronta para análise, em vez de um bloco Message.",
      },
      {
        name: "Coluna XML bruto opcional",
        body: "Marque “Coluna XML bruto” antes de exportar para adicionar o XML <Event> completo de cada evento como a última coluna, para quando você precisar de um campo que a tabela não mostra.",
      },
      {
        name: "Codificação compatível com Excel",
        body: "O CSV está em UTF-8 com marca de ordem de bytes (BOM), então o Excel abre nomes de usuário acentuados, caminhos não latinos e texto de script PowerShell sem corrompê-los.",
      },
    ],
    stepsHeading: "Como converter EVTX para CSV",
    steps: [
      {
        title: "Abra o conversor",
        body: "Abra a página inicial do EVTX parser. O parser WebAssembly carrega na sua aba; nada é enviado a um servidor.",
      },
      {
        title: "Solte seu arquivo .evtx",
        body: "Arraste Security.evtx, System.evtx, um log do Sysmon ou PowerShell para a área de soltar, ou clique para escolher um. Vários arquivos podem ser carregados juntos.",
      },
      {
        title: "Filtre e depois Exportar CSV",
        body: "Refine as linhas com a barra de filtro, os chips de Event ID ou a linha do tempo, depois clique em “Exportar CSV”. Somente as linhas filtradas são gravadas, e o arquivo é baixado localmente.",
      },
    ],
    faqHeading: "Perguntas frequentes sobre EVTX para CSV",
    faq: [
      {
        q: "Como converto EVTX para CSV com PowerShell?",
        a: "No Windows: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation. Isso requer um host Windows e coloca todos os campos do evento na única coluna Message; o conversor no navegador separa o EventData em colunas distintas e funciona em qualquer sistema operacional.",
      },
      {
        q: "O Event Viewer consegue salvar um arquivo EVTX como CSV?",
        a: "Sim: abra o log, escolha “Save All Events As…” e selecione CSV (Comma Separated). O resultado mantém apenas as colunas de resumo mais o texto da mensagem renderizada, então você perde os campos EventData estruturados.",
      },
      {
        q: "Como converto EVTX para CSV no Linux ou macOS?",
        a: "Use este conversor no navegador, ou uma ferramenta de linha de comando como EvtxECmd (--csv) ou evtx_dump combinada com uma etapa de JSON para CSV. Todas analisam o formato binário diretamente, sem Windows.",
      },
      {
        q: "Meu arquivo EVTX é enviado durante a conversão?",
        a: "Não. O arquivo é lido na memória do seu navegador e convertido lá. Você pode se desconectar da rede depois que a página carregar, e a conversão continua funcionando.",
      },
    ],
  },
  ja: {
    metaTitle: "EVTX を CSV に変換 — 無料・アップロード不要",
    metaDescription:
      "Windows の .evtx イベントログをブラウザで CSV に変換し、Excel で開けます。無料の EVTX から CSV への変換ツール — アップロード不要、インストール不要。EventData フィールドが実際の列になります。",
    h1: "EVTX を CSV に変換",
    intro:
      "Windows の .evtx イベントログを、ブラウザ上で直接 Excel、LibreOffice、pandas で開ける CSV に変換します。ファイルは WebAssembly にコンパイルされた Rust パーサーによってローカルで解析されるため、何もアップロードされず、Windows ホストも不要です。",
    ctaLabel: "EVTX から CSV への変換ツールを開く",
    formatsHeading: "CSV に含まれる内容",
    formats: [
      {
        name: "イベントごとに 1 行",
        body: "各レコードは、共通の列（レコード番号、タイムスタンプ（UTC）、レベル、Event ID、プロバイダー、チャネル、コンピューター）を持つ 1 行になります。複数の .evtx ファイルを一度に読み込むと、Source 列でどのファイル由来の行かが分かります。",
      },
      {
        name: "EventData が実際の列に",
        body: "各 EventData フィールド（TargetUserName、LogonType、IpAddress、CommandLine…）は、それぞれ独自の列を持ちます。まず単一の Event ID（4624、4688、Sysmon 1 など）で絞り込むと、Message の塊の代わりに、分析しやすいきれいな表が得られます。",
      },
      {
        name: "オプションの生 XML 列",
        body: "エクスポート前に「生 XML 列」にチェックを入れると、各イベントの完全な <Event> XML が最後の列として追加されます。表に表示されないフィールドが必要な場合に使用します。",
      },
      {
        name: "Excel に適したエンコーディング",
        body: "CSV は BOM（バイトオーダーマーク）付きの UTF-8 なので、Excel はアクセント付きユーザー名、非ラテン文字のパス、PowerShell スクリプトのテキストを文字化けさせずに開けます。",
      },
    ],
    stepsHeading: "EVTX を CSV に変換する方法",
    steps: [
      {
        title: "変換ツールを開く",
        body: "EVTX parser のホームページを開きます。WebAssembly パーサーがタブ内に読み込まれます。サーバーには何も送信されません。",
      },
      {
        title: ".evtx ファイルをドロップする",
        body: "Security.evtx、System.evtx、Sysmon または PowerShell のログをドロップゾーンにドラッグするか、クリックして選択します。複数のファイルをまとめて読み込むこともできます。",
      },
      {
        title: "絞り込んでから CSV をエクスポート",
        body: "フィルターバー、Event ID のチップ、またはタイムラインで行を絞り込んでから、「CSV をエクスポート」をクリックします。絞り込まれた行だけが書き出され、ファイルはローカルにダウンロードされます。",
      },
    ],
    faqHeading: "EVTX から CSV への変換に関する FAQ",
    faq: [
      {
        q: "PowerShell で EVTX を CSV に変換するには？",
        a: "Windows では次のようにします: Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation。Windows ホストが必要で、すべてのイベントフィールドが単一の Message 列にまとめられます。ブラウザ内の変換ツールは EventData を個別の列に分割し、どの OS でも動作します。",
      },
      {
        q: "Event Viewer は EVTX ファイルを CSV として保存できますか？",
        a: "はい。ログを開き、「Save All Events As…」を選択して CSV (Comma Separated) を選びます。出力にはサマリー列とレンダリングされたメッセージテキストのみが残るため、構造化された EventData フィールドは失われます。",
      },
      {
        q: "Linux や macOS で EVTX を CSV に変換するには？",
        a: "このブラウザベースの変換ツールを使うか、EvtxECmd（--csv）や evtx_dump を JSON から CSV への変換ステップと組み合わせたコマンドラインツールを使います。いずれも Windows なしでバイナリ形式を直接解析します。",
      },
      {
        q: "変換中に EVTX ファイルはアップロードされますか？",
        a: "いいえ。ファイルはブラウザのメモリに読み込まれ、その場で変換されます。ページ読み込み後にネットワークを切断しても、変換は動作し続けます。",
      },
    ],
  },
  zh: {
    metaTitle: "EVTX 转 CSV 转换器——免费，无需上传",
    metaDescription:
      "在浏览器中将 Windows .evtx 事件日志转换为 CSV，并在 Excel 中打开。免费的 EVTX 转 CSV 转换器——无需上传，无需安装。EventData 字段将变为真正的列。",
    h1: "将 EVTX 转换为 CSV",
    intro:
      "直接在浏览器中将 Windows .evtx 事件日志转换为可在 Excel、LibreOffice 或 pandas 中打开的 CSV。文件由编译为 WebAssembly 的 Rust 解析器在本地解析，因此不会上传任何内容，也无需 Windows 主机。",
    ctaLabel: "打开 EVTX 转 CSV 转换器",
    formatsHeading: "CSV 包含的内容",
    formats: [
      {
        name: "每个事件一行",
        body: "每条记录都会变成一行，包含常用列：记录编号、时间戳（UTC）、级别、Event ID、提供程序、通道和计算机。当您同时加载多个 .evtx 文件时，Source 列会指明每一行来自哪个文件。",
      },
      {
        name: "EventData 变为真正的列",
        body: "每个 EventData 字段（TargetUserName、LogonType、IpAddress、CommandLine…）都会获得自己的列。先筛选到单个 Event ID——如 4624、4688、Sysmon 1——即可得到干净、可直接分析的表格，而不是一个 Message 大文本块。",
      },
      {
        name: "可选的原始 XML 列",
        body: "在导出前勾选“原始 XML 列”，即可将每个事件完整的 <Event> XML 添加为最后一列，适用于需要表格未显示的字段的情况。",
      },
      {
        name: "兼容 Excel 的编码",
        body: "该 CSV 采用带字节顺序标记（BOM）的 UTF-8 编码，因此 Excel 打开带重音的用户名、非拉丁字符路径和 PowerShell 脚本文本时不会出现乱码。",
      },
    ],
    stepsHeading: "如何将 EVTX 转换为 CSV",
    steps: [
      {
        title: "打开转换器",
        body: "打开 EVTX parser 主页。WebAssembly 解析器会在您的标签页中加载；不会向任何服务器发送任何内容。",
      },
      {
        title: "拖入您的 .evtx 文件",
        body: "将 Security.evtx、System.evtx、Sysmon 或 PowerShell 日志拖到拖放区，或单击选择一个。可以一起加载多个文件。",
      },
      {
        title: "筛选后导出 CSV",
        body: "使用筛选栏、Event ID 标签或时间线缩小行范围，然后单击“导出 CSV”。只会写入筛选后的行，文件将下载到本地。",
      },
    ],
    faqHeading: "关于 EVTX 转 CSV 的常见问题",
    faq: [
      {
        q: "如何使用 PowerShell 将 EVTX 转换为 CSV？",
        a: "在 Windows 上：Get-WinEvent -Path .\\Security.evtx | Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv events.csv -NoTypeInformation。这需要 Windows 主机，并将所有事件字段放入单个 Message 列；浏览器内转换器会将 EventData 拆分为独立的列，且可在任何操作系统上运行。",
      },
      {
        q: "Event Viewer 能否将 EVTX 文件另存为 CSV？",
        a: "可以：打开日志，选择「Save All Events As…」，然后选择 CSV (Comma Separated)。输出只保留摘要列和渲染后的消息文本，因此您会丢失结构化的 EventData 字段。",
      },
      {
        q: "如何在 Linux 或 macOS 上将 EVTX 转换为 CSV？",
        a: "使用这个基于浏览器的转换器，或使用 EvtxECmd（--csv）之类的命令行工具，或将 evtx_dump 与 JSON 转 CSV 步骤结合使用。它们都可以直接解析二进制格式，无需 Windows。",
      },
      {
        q: "转换过程中我的 EVTX 文件会被上传吗？",
        a: "不会。文件会被读入浏览器内存并在本地转换。页面加载完成后，您可以断开网络连接，转换仍然可以正常工作。",
      },
    ],
  },
};
