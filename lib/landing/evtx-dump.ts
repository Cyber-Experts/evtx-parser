import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";

export const EVTX_DUMP: LocaleContent<LandingContent> = {
  en: {
    metaTitle: "evtx_dump online — the Rust EVTX parser in your browser",
    metaDescription:
      "Run evtx_dump without installing it: this site is the omerbenamram/evtx Rust parser compiled to WebAssembly. evtx_dump usage, flags and JSON/XML output explained.",
    h1: "evtx_dump online: parse EVTX without installing anything",
    intro:
      "evtx_dump is the command-line tool of omerbenamram/evtx, the fast Rust parser for Windows .evtx event logs. EVTX parser is that same parser compiled to WebAssembly, so you get evtx_dump's output in a browser tab — no Rust toolchain, no binary download, and the file is never uploaded.",
    ctaLabel: "Open evtx_dump in your browser",
    formatsHeading: "evtx_dump usage",
    formats: [
      {
        name: "Install",
        body: "Download a prebuilt binary for Windows, macOS or Linux from the project's GitHub releases, or build it with Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Dump to XML (default)",
        body: "With no options, evtx_dump prints every record as XML, the same structure Event Viewer's XML view shows.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Dump to JSON or JSON Lines",
        body: "-o json prints JSON records; -o jsonl prints one JSON object per line, which is what jq, Elastic and most bulk loaders want.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. this site",
        body: "Use evtx_dump for scripting, very large collections and many hosts at once. Use the browser version for ad-hoc triage: you get filtering, an Event ID breakdown, a timeline, built-in detections and CSV, TXT, JSON or XML export without installing anything.",
      },
    ],
    stepsHeading: "How to use evtx_dump in the browser",
    steps: [
      {
        title: "Open EVTX parser",
        body: "Open the homepage. The WebAssembly build of the evtx crate loads in a Web Worker.",
      },
      {
        title: "Drop your .evtx files",
        body: "Drag one or several .evtx files onto the drop zone. They are parsed locally, record by record, just like evtx_dump would.",
      },
      {
        title: "Inspect or export",
        body: "Filter and inspect each event's rebuilt XML, then export to JSON, CSV, TXT or XML.",
      },
    ],
    faqHeading: "evtx_dump FAQ",
    faq: [
      {
        q: "What is evtx_dump?",
        a: "evtx_dump is the CLI shipped with the omerbenamram/evtx Rust crate. It reads a Windows .evtx file and prints each record as XML, JSON or JSON Lines, using multiple threads. It is MIT/Apache licensed and runs on Windows, macOS and Linux.",
      },
      {
        q: "Is this site really the same parser as evtx_dump?",
        a: "Yes. The parsing core is the evtx crate compiled to WebAssembly, so records are rebuilt the same way. The difference is the interface: a browser UI with filters and exports instead of a command line.",
      },
      {
        q: "evtx_dump vs. python-evtx vs. EvtxECmd?",
        a: "evtx_dump (Rust) is the fastest and outputs XML/JSON. python-evtx is convenient inside Python scripts but much slower. EvtxECmd (Eric Zimmerman) normalises events into CSV/JSON with maps per Event ID and is popular in Windows-centric DFIR workflows.",
      },
      {
        q: "Can evtx_dump read corrupted or partial EVTX files?",
        a: "It is tolerant of damaged chunks and skips records it cannot parse instead of aborting. For carving records out of unallocated space, see our guide on recovering deleted EVTX records.",
      },
    ],
  },
  fr: {
    metaTitle: "evtx_dump en ligne — l'analyseur EVTX Rust dans le navigateur",
    metaDescription:
      "Utilisez evtx_dump sans l'installer : ce site est l'analyseur Rust omerbenamram/evtx compilé en WebAssembly. Usage, options et sortie JSON/XML d'evtx_dump expliqués.",
    h1: "evtx_dump en ligne : analyser un EVTX sans rien installer",
    intro:
      "evtx_dump est l'outil en ligne de commande d'omerbenamram/evtx, l'analyseur Rust rapide pour les journaux d'événements Windows .evtx. EVTX parser est ce même analyseur compilé en WebAssembly, vous obtenez donc la sortie d'evtx_dump dans un onglet de navigateur — sans toolchain Rust, sans téléchargement de binaire, et le fichier n'est jamais envoyé.",
    ctaLabel: "Ouvrir evtx_dump dans le navigateur",
    formatsHeading: "Usage d'evtx_dump",
    formats: [
      {
        name: "Installation",
        body: "Téléchargez un binaire prêt à l'emploi pour Windows, macOS ou Linux depuis les releases GitHub du projet, ou compilez-le avec Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Analyser vers XML (par défaut)",
        body: "Sans option, evtx_dump affiche chaque enregistrement en XML, la même structure que la vue XML de l'Observateur d'événements.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Analyser vers JSON ou JSON Lines",
        body: "-o json affiche des enregistrements JSON ; -o jsonl affiche un objet JSON par ligne, ce que jq, Elastic et la plupart des outils de chargement en masse attendent.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. ce site",
        body: "Utilisez evtx_dump pour le scripting, les très grandes collections et plusieurs hôtes à la fois. Utilisez la version navigateur pour le tri ponctuel : vous obtenez le filtrage, une répartition par Event ID, une chronologie, des détections intégrées et un export CSV, TXT, JSON ou XML sans rien installer.",
      },
    ],
    stepsHeading: "Comment utiliser evtx_dump dans le navigateur",
    steps: [
      {
        title: "Ouvrir EVTX parser",
        body: "Ouvrez la page d'accueil. La version WebAssembly du crate evtx se charge dans un Web Worker.",
      },
      {
        title: "Déposez vos fichiers .evtx",
        body: "Glissez un ou plusieurs fichiers .evtx dans la zone de dépôt. Ils sont analysés localement, enregistrement par enregistrement, exactement comme le ferait evtx_dump.",
      },
      {
        title: "Inspecter ou exporter",
        body: "Filtrez et inspectez le XML reconstruit de chaque événement, puis exportez en JSON, CSV, TXT ou XML.",
      },
    ],
    faqHeading: "FAQ evtx_dump",
    faq: [
      {
        q: "Qu'est-ce qu'evtx_dump ?",
        a: "evtx_dump est le CLI fourni avec le crate Rust omerbenamram/evtx. Il lit un fichier Windows .evtx et affiche chaque enregistrement en XML, JSON ou JSON Lines, en utilisant plusieurs threads. Il est sous licence MIT/Apache et fonctionne sur Windows, macOS et Linux.",
      },
      {
        q: "Ce site est-il vraiment le même analyseur qu'evtx_dump ?",
        a: "Oui. Le cœur d'analyse est le crate evtx compilé en WebAssembly, donc les enregistrements sont reconstruits de la même manière. La différence, c'est l'interface : une UI de navigateur avec filtres et exports au lieu d'une ligne de commande.",
      },
      {
        q: "evtx_dump vs. python-evtx vs. EvtxECmd ?",
        a: "evtx_dump (Rust) est le plus rapide et produit du XML/JSON. python-evtx est pratique dans des scripts Python mais bien plus lent. EvtxECmd (Eric Zimmerman) normalise les événements en CSV/JSON avec des mappings par Event ID et est populaire dans les workflows DFIR centrés sur Windows.",
      },
      {
        q: "evtx_dump peut-il lire des fichiers EVTX corrompus ou partiels ?",
        a: "Il tolère les chunks endommagés et ignore les enregistrements qu'il ne peut pas analyser au lieu d'échouer complètement. Pour extraire des enregistrements depuis de l'espace non alloué, consultez notre guide sur la récupération d'enregistrements EVTX supprimés.",
      },
    ],
  },
  de: {
    metaTitle: "evtx_dump online — der Rust-EVTX-Parser im Browser",
    metaDescription:
      "Nutzen Sie evtx_dump, ohne es zu installieren: Diese Seite ist der omerbenamram/evtx-Rust-Parser, kompiliert zu WebAssembly. evtx_dump-Nutzung, Flags und JSON/XML-Ausgabe erklärt.",
    h1: "evtx_dump online: EVTX analysieren, ohne etwas zu installieren",
    intro:
      "evtx_dump ist das Kommandozeilen-Tool von omerbenamram/evtx, dem schnellen Rust-Parser für Windows-.evtx-Ereignisprotokolle. EVTX parser ist derselbe Parser, kompiliert zu WebAssembly, sodass Sie die Ausgabe von evtx_dump in einem Browser-Tab erhalten — ohne Rust-Toolchain, ohne Binary-Download, und die Datei wird nie hochgeladen.",
    ctaLabel: "evtx_dump im Browser öffnen",
    formatsHeading: "evtx_dump-Nutzung",
    formats: [
      {
        name: "Installation",
        body: "Laden Sie ein vorgefertigtes Binary für Windows, macOS oder Linux von den GitHub-Releases des Projekts herunter, oder bauen Sie es mit Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Nach XML dumpen (Standard)",
        body: "Ohne Optionen gibt evtx_dump jeden Datensatz als XML aus, dieselbe Struktur, die die XML-Ansicht der Ereignisanzeige zeigt.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Nach JSON oder JSON Lines dumpen",
        body: "-o json gibt JSON-Datensätze aus; -o jsonl gibt ein JSON-Objekt pro Zeile aus, was jq, Elastic und die meisten Bulk-Loader erwarten.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. diese Seite",
        body: "Nutzen Sie evtx_dump für Scripting, sehr große Sammlungen und viele Hosts gleichzeitig. Nutzen Sie die Browser-Version für Ad-hoc-Triage: Sie erhalten Filterung, eine Event-ID-Aufschlüsselung, eine Zeitleiste, integrierte Erkennungen und CSV-, TXT-, JSON- oder XML-Export, ohne etwas zu installieren.",
      },
    ],
    stepsHeading: "So nutzen Sie evtx_dump im Browser",
    steps: [
      {
        title: "EVTX parser öffnen",
        body: "Öffnen Sie die Startseite. Der WebAssembly-Build des evtx-Crates lädt in einem Web Worker.",
      },
      {
        title: "Legen Sie Ihre .evtx-Dateien ab",
        body: "Ziehen Sie eine oder mehrere .evtx-Dateien in die Ablagezone. Sie werden lokal analysiert, Datensatz für Datensatz, genau wie es evtx_dump tun würde.",
      },
      {
        title: "Prüfen oder exportieren",
        body: "Filtern und prüfen Sie das rekonstruierte XML jedes Ereignisses und exportieren Sie dann nach JSON, CSV, TXT oder XML.",
      },
    ],
    faqHeading: "evtx_dump-FAQ",
    faq: [
      {
        q: "Was ist evtx_dump?",
        a: "evtx_dump ist das CLI, das mit dem Rust-Crate omerbenamram/evtx ausgeliefert wird. Es liest eine Windows-.evtx-Datei und gibt jeden Datensatz als XML, JSON oder JSON Lines aus, unter Nutzung mehrerer Threads. Es ist MIT/Apache-lizenziert und läuft unter Windows, macOS und Linux.",
      },
      {
        q: "Ist diese Seite wirklich derselbe Parser wie evtx_dump?",
        a: "Ja. Der Parsing-Kern ist das zu WebAssembly kompilierte evtx-Crate, sodass Datensätze auf dieselbe Weise rekonstruiert werden. Der Unterschied ist die Oberfläche: eine Browser-UI mit Filtern und Exporten statt einer Kommandozeile.",
      },
      {
        q: "evtx_dump vs. python-evtx vs. EvtxECmd?",
        a: "evtx_dump (Rust) ist am schnellsten und gibt XML/JSON aus. python-evtx ist praktisch innerhalb von Python-Skripten, aber deutlich langsamer. EvtxECmd (Eric Zimmerman) normalisiert Ereignisse in CSV/JSON mit Maps pro Event ID und ist in Windows-zentrierten DFIR-Workflows beliebt.",
      },
      {
        q: "Kann evtx_dump beschädigte oder unvollständige EVTX-Dateien lesen?",
        a: "Es toleriert beschädigte Chunks und überspringt Datensätze, die es nicht analysieren kann, statt abzubrechen. Zum Carven von Datensätzen aus nicht zugewiesenem Speicherplatz siehe unseren Leitfaden zum Wiederherstellen gelöschter EVTX-Datensätze.",
      },
    ],
  },
  es: {
    metaTitle: "evtx_dump online — el analizador EVTX en Rust en el navegador",
    metaDescription:
      "Usa evtx_dump sin instalarlo: este sitio es el analizador Rust omerbenamram/evtx compilado a WebAssembly. Uso, flags y salida JSON/XML de evtx_dump explicados.",
    h1: "evtx_dump online: analiza EVTX sin instalar nada",
    intro:
      "evtx_dump es la herramienta de línea de comandos de omerbenamram/evtx, el analizador Rust rápido para registros de eventos de Windows .evtx. EVTX parser es ese mismo analizador compilado a WebAssembly, así que obtienes la salida de evtx_dump en una pestaña del navegador — sin toolchain de Rust, sin descargar un binario, y el archivo nunca se sube.",
    ctaLabel: "Abrir evtx_dump en el navegador",
    formatsHeading: "Uso de evtx_dump",
    formats: [
      {
        name: "Instalación",
        body: "Descarga un binario precompilado para Windows, macOS o Linux desde las releases de GitHub del proyecto, o compílalo con Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Volcar a XML (por defecto)",
        body: "Sin opciones, evtx_dump imprime cada registro como XML, la misma estructura que muestra la vista XML del Visor de eventos.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Volcar a JSON o JSON Lines",
        body: "-o json imprime registros JSON; -o jsonl imprime un objeto JSON por línea, que es lo que quieren jq, Elastic y la mayoría de los cargadores masivos.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. este sitio",
        body: "Usa evtx_dump para scripting, colecciones muy grandes y muchos hosts a la vez. Usa la versión del navegador para triaje puntual: obtienes filtrado, un desglose por Event ID, una línea de tiempo, detecciones integradas y exportación a CSV, TXT, JSON o XML sin instalar nada.",
      },
    ],
    stepsHeading: "Cómo usar evtx_dump en el navegador",
    steps: [
      {
        title: "Abre EVTX parser",
        body: "Abre la página de inicio. La compilación WebAssembly del crate evtx se carga en un Web Worker.",
      },
      {
        title: "Suelta tus archivos .evtx",
        body: "Arrastra uno o varios archivos .evtx a la zona de soltar. Se analizan localmente, registro por registro, igual que lo haría evtx_dump.",
      },
      {
        title: "Inspecciona o exporta",
        body: "Filtra e inspecciona el XML reconstruido de cada evento, luego exporta a JSON, CSV, TXT o XML.",
      },
    ],
    faqHeading: "Preguntas frecuentes sobre evtx_dump",
    faq: [
      {
        q: "¿Qué es evtx_dump?",
        a: "evtx_dump es el CLI incluido con el crate Rust omerbenamram/evtx. Lee un archivo Windows .evtx e imprime cada registro como XML, JSON o JSON Lines, usando múltiples hilos. Tiene licencia MIT/Apache y funciona en Windows, macOS y Linux.",
      },
      {
        q: "¿Este sitio es realmente el mismo analizador que evtx_dump?",
        a: "Sí. El núcleo de análisis es el crate evtx compilado a WebAssembly, así que los registros se reconstruyen de la misma manera. La diferencia es la interfaz: una UI de navegador con filtros y exportaciones en lugar de una línea de comandos.",
      },
      {
        q: "¿evtx_dump frente a python-evtx frente a EvtxECmd?",
        a: "evtx_dump (Rust) es el más rápido y produce XML/JSON. python-evtx es cómodo dentro de scripts de Python pero mucho más lento. EvtxECmd (Eric Zimmerman) normaliza eventos en CSV/JSON con mapeos por Event ID y es popular en flujos de trabajo DFIR centrados en Windows.",
      },
      {
        q: "¿Puede evtx_dump leer archivos EVTX dañados o parciales?",
        a: "Tolera chunks dañados y omite los registros que no puede analizar en lugar de abortar. Para extraer registros de espacio no asignado, consulta nuestra guía sobre recuperación de registros EVTX eliminados.",
      },
    ],
  },
  it: {
    metaTitle: "evtx_dump online — il parser EVTX in Rust nel browser",
    metaDescription:
      "Usa evtx_dump senza installarlo: questo sito è il parser Rust omerbenamram/evtx compilato in WebAssembly. Uso, flag e output JSON/XML di evtx_dump spiegati.",
    h1: "evtx_dump online: analizza EVTX senza installare nulla",
    intro:
      "evtx_dump è lo strumento da riga di comando di omerbenamram/evtx, il parser Rust veloce per i registri eventi Windows .evtx. EVTX parser è lo stesso parser compilato in WebAssembly, quindi ottieni l'output di evtx_dump in una scheda del browser — senza toolchain Rust, senza scaricare un binario, e il file non viene mai caricato.",
    ctaLabel: "Apri evtx_dump nel browser",
    formatsHeading: "Uso di evtx_dump",
    formats: [
      {
        name: "Installazione",
        body: "Scarica un binario precompilato per Windows, macOS o Linux dalle release GitHub del progetto, oppure compilalo con Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Esportare in XML (predefinito)",
        body: "Senza opzioni, evtx_dump stampa ogni record come XML, la stessa struttura mostrata dalla vista XML del Visualizzatore eventi.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Esportare in JSON o JSON Lines",
        body: "-o json stampa record JSON; -o jsonl stampa un oggetto JSON per riga, ciò che jq, Elastic e la maggior parte dei loader di massa vogliono.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. questo sito",
        body: "Usa evtx_dump per lo scripting, raccolte molto grandi e molti host contemporaneamente. Usa la versione browser per il triage estemporaneo: ottieni filtri, una ripartizione per Event ID, una timeline, rilevamenti integrati ed esportazione CSV, TXT, JSON o XML senza installare nulla.",
      },
    ],
    stepsHeading: "Come usare evtx_dump nel browser",
    steps: [
      {
        title: "Apri EVTX parser",
        body: "Apri la homepage. La build WebAssembly del crate evtx si carica in un Web Worker.",
      },
      {
        title: "Rilascia i tuoi file .evtx",
        body: "Trascina uno o più file .evtx nell'area di rilascio. Vengono analizzati localmente, record per record, esattamente come farebbe evtx_dump.",
      },
      {
        title: "Ispeziona o esporta",
        body: "Filtra e ispeziona l'XML ricostruito di ogni evento, poi esporta in JSON, CSV, TXT o XML.",
      },
    ],
    faqHeading: "FAQ su evtx_dump",
    faq: [
      {
        q: "Cos'è evtx_dump?",
        a: "evtx_dump è il CLI incluso nel crate Rust omerbenamram/evtx. Legge un file Windows .evtx e stampa ogni record come XML, JSON o JSON Lines, usando più thread. È con licenza MIT/Apache e funziona su Windows, macOS e Linux.",
      },
      {
        q: "Questo sito è davvero lo stesso parser di evtx_dump?",
        a: "Sì. Il nucleo di parsing è il crate evtx compilato in WebAssembly, quindi i record vengono ricostruiti allo stesso modo. La differenza è l'interfaccia: una UI da browser con filtri ed esportazioni invece di una riga di comando.",
      },
      {
        q: "evtx_dump vs. python-evtx vs. EvtxECmd?",
        a: "evtx_dump (Rust) è il più veloce e produce XML/JSON. python-evtx è comodo dentro script Python ma molto più lento. EvtxECmd (Eric Zimmerman) normalizza gli eventi in CSV/JSON con mappe per Event ID ed è diffuso nei flussi di lavoro DFIR incentrati su Windows.",
      },
      {
        q: "evtx_dump può leggere file EVTX corrotti o parziali?",
        a: "Tollera chunk danneggiati e salta i record che non riesce ad analizzare invece di interrompersi. Per recuperare record da spazio non allocato, consulta la nostra guida sul recupero di record EVTX eliminati.",
      },
    ],
  },
  pt: {
    metaTitle: "evtx_dump online — o parser EVTX em Rust no navegador",
    metaDescription:
      "Use o evtx_dump sem instalá-lo: este site é o parser Rust omerbenamram/evtx compilado para WebAssembly. Uso, flags e saída JSON/XML do evtx_dump explicados.",
    h1: "evtx_dump online: analise EVTX sem instalar nada",
    intro:
      "evtx_dump é a ferramenta de linha de comando do omerbenamram/evtx, o parser Rust rápido para logs de eventos do Windows .evtx. EVTX parser é esse mesmo parser compilado para WebAssembly, então você obtém a saída do evtx_dump em uma aba do navegador — sem toolchain Rust, sem baixar um binário, e o arquivo nunca é enviado.",
    ctaLabel: "Abrir o evtx_dump no navegador",
    formatsHeading: "Uso do evtx_dump",
    formats: [
      {
        name: "Instalação",
        body: "Baixe um binário pronto para Windows, macOS ou Linux nas releases do GitHub do projeto, ou compile-o com o Cargo.",
        code: "cargo install evtx",
      },
      {
        name: "Exportar para XML (padrão)",
        body: "Sem opções, o evtx_dump imprime cada registro como XML, a mesma estrutura que a visão XML do Visualizador de Eventos mostra.",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "Exportar para JSON ou JSON Lines",
        body: "-o json imprime registros JSON; -o jsonl imprime um objeto JSON por linha, o que jq, Elastic e a maioria dos carregadores em lote esperam.",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump vs. este site",
        body: "Use o evtx_dump para scripting, coleções muito grandes e vários hosts ao mesmo tempo. Use a versão do navegador para triagem pontual: você obtém filtragem, uma repartição por Event ID, uma linha do tempo, detecções integradas e exportação para CSV, TXT, JSON ou XML sem instalar nada.",
      },
    ],
    stepsHeading: "Como usar o evtx_dump no navegador",
    steps: [
      {
        title: "Abra o EVTX parser",
        body: "Abra a página inicial. A build WebAssembly do crate evtx carrega em um Web Worker.",
      },
      {
        title: "Solte seus arquivos .evtx",
        body: "Arraste um ou vários arquivos .evtx para a área de soltar. Eles são analisados localmente, registro por registro, exatamente como o evtx_dump faria.",
      },
      {
        title: "Inspecione ou exporte",
        body: "Filtre e inspecione o XML reconstruído de cada evento, depois exporte para JSON, CSV, TXT ou XML.",
      },
    ],
    faqHeading: "FAQ do evtx_dump",
    faq: [
      {
        q: "O que é o evtx_dump?",
        a: "evtx_dump é o CLI que acompanha o crate Rust omerbenamram/evtx. Ele lê um arquivo Windows .evtx e imprime cada registro como XML, JSON ou JSON Lines, usando múltiplas threads. É licenciado sob MIT/Apache e roda em Windows, macOS e Linux.",
      },
      {
        q: "Este site é realmente o mesmo parser que o evtx_dump?",
        a: "Sim. O núcleo de análise é o crate evtx compilado para WebAssembly, então os registros são reconstruídos da mesma forma. A diferença é a interface: uma UI de navegador com filtros e exportações em vez de uma linha de comando.",
      },
      {
        q: "evtx_dump vs. python-evtx vs. EvtxECmd?",
        a: "evtx_dump (Rust) é o mais rápido e gera XML/JSON. python-evtx é conveniente dentro de scripts Python, mas bem mais lento. EvtxECmd (Eric Zimmerman) normaliza eventos em CSV/JSON com mapeamentos por Event ID e é popular em workflows de DFIR centrados em Windows.",
      },
      {
        q: "O evtx_dump consegue ler arquivos EVTX corrompidos ou parciais?",
        a: "Ele tolera chunks danificados e pula registros que não consegue analisar em vez de abortar. Para extrair registros de espaço não alocado, veja nosso guia sobre recuperação de registros EVTX excluídos.",
      },
    ],
  },
  ja: {
    metaTitle: "evtx_dump オンライン — ブラウザで動く Rust 製 EVTX パーサー",
    metaDescription:
      "evtx_dump をインストールせずに利用: このサイトは omerbenamram/evtx の Rust パーサーを WebAssembly にコンパイルしたものです。evtx_dump の使い方、フラグ、JSON/XML 出力を解説。",
    h1: "evtx_dump オンライン：何もインストールせずに EVTX を解析",
    intro:
      "evtx_dump は、Windows の .evtx イベントログ用の高速な Rust パーサーである omerbenamram/evtx のコマンドラインツールです。EVTX parser はその同じパーサーを WebAssembly にコンパイルしたものなので、ブラウザのタブで evtx_dump と同じ出力が得られます — Rust のツールチェーンもバイナリのダウンロードも不要で、ファイルがアップロードされることもありません。",
    ctaLabel: "ブラウザで evtx_dump を開く",
    formatsHeading: "evtx_dump の使い方",
    formats: [
      {
        name: "インストール",
        body: "プロジェクトの GitHub リリースから Windows、macOS、Linux 向けのビルド済みバイナリをダウンロードするか、Cargo でビルドしてください。",
        code: "cargo install evtx",
      },
      {
        name: "XML へダンプ（デフォルト）",
        body: "オプションなしの場合、evtx_dump は各レコードを XML として出力します。これはイベントビューアーの XML 表示と同じ構造です。",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "JSON または JSON Lines へダンプ",
        body: "-o json は JSON レコードを出力し、-o jsonl は 1 行に 1 つの JSON オブジェクトを出力します。これは jq、Elastic、ほとんどの一括ローダーが求める形式です。",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump とこのサイトの比較",
        body: "スクリプト処理、非常に大きなコレクション、複数ホストの一括処理には evtx_dump を使ってください。臨時のトリアージにはブラウザ版を使ってください。フィルタリング、Event ID の内訳、タイムライン、組み込みの検知、CSV・TXT・JSON・XML へのエクスポートが、何もインストールせずに利用できます。",
      },
    ],
    stepsHeading: "ブラウザで evtx_dump を使う方法",
    steps: [
      {
        title: "EVTX parser を開く",
        body: "ホームページを開きます。evtx クレートの WebAssembly ビルドが Web Worker 内に読み込まれます。",
      },
      {
        title: ".evtx ファイルをドロップする",
        body: "1 つまたは複数の .evtx ファイルをドロップゾーンにドラッグします。evtx_dump と同様に、レコードごとにローカルで解析されます。",
      },
      {
        title: "確認またはエクスポート",
        body: "各イベントの再構築された XML をフィルタリング・確認し、JSON、CSV、TXT、XML へエクスポートします。",
      },
    ],
    faqHeading: "evtx_dump に関する FAQ",
    faq: [
      {
        q: "evtx_dump とは何ですか？",
        a: "evtx_dump は Rust クレート omerbenamram/evtx に同梱される CLI です。Windows の .evtx ファイルを読み込み、複数スレッドを使って各レコードを XML、JSON、JSON Lines として出力します。MIT/Apache ライセンスで、Windows、macOS、Linux で動作します。",
      },
      {
        q: "このサイトは本当に evtx_dump と同じパーサーですか？",
        a: "はい。解析コアは WebAssembly にコンパイルされた evtx クレートなので、レコードは同じ方法で再構築されます。違いはインターフェースだけです — コマンドラインではなく、フィルターとエクスポート機能を備えたブラウザ UI です。",
      },
      {
        q: "evtx_dump と python-evtx、EvtxECmd の比較は？",
        a: "evtx_dump（Rust）は最速で、XML/JSON を出力します。python-evtx は Python スクリプト内で扱いやすいですが、かなり低速です。EvtxECmd（Eric Zimmerman 作）は Event ID ごとのマップを使ってイベントを CSV/JSON に正規化し、Windows 中心の DFIR ワークフローで人気です。",
      },
      {
        q: "evtx_dump は破損・一部欠損した EVTX ファイルを読めますか？",
        a: "破損したチャンクを許容し、解析できないレコードは中断せずにスキップします。未割り当て領域からレコードをカービングする方法については、削除された EVTX レコードの復元ガイドをご覧ください。",
      },
    ],
  },
  zh: {
    metaTitle: "evtx_dump 在线版——运行在浏览器中的 Rust EVTX 解析器",
    metaDescription:
      "无需安装即可使用 evtx_dump：本站是编译为 WebAssembly 的 omerbenamram/evtx Rust 解析器。详解 evtx_dump 的用法、参数与 JSON/XML 输出。",
    h1: "evtx_dump 在线版：无需安装即可解析 EVTX",
    intro:
      "evtx_dump 是 omerbenamram/evtx 的命令行工具，是用于 Windows .evtx 事件日志的快速 Rust 解析器。EVTX parser 就是同一个解析器编译为 WebAssembly 的版本，因此您可以在浏览器标签页中获得与 evtx_dump 相同的输出——无需 Rust 工具链，无需下载二进制文件，且文件绝不会被上传。",
    ctaLabel: "在浏览器中打开 evtx_dump",
    formatsHeading: "evtx_dump 用法",
    formats: [
      {
        name: "安装",
        body: "从项目的 GitHub releases 下载适用于 Windows、macOS 或 Linux 的预编译二进制文件，或使用 Cargo 自行构建。",
        code: "cargo install evtx",
      },
      {
        name: "导出为 XML（默认）",
        body: "不带任何选项时，evtx_dump 会将每条记录打印为 XML，与事件查看器的 XML 视图结构相同。",
        code: "evtx_dump Security.evtx > security.xml",
      },
      {
        name: "导出为 JSON 或 JSON Lines",
        body: "-o json 打印 JSON 记录；-o jsonl 每行打印一个 JSON 对象，这正是 jq、Elastic 及大多数批量加载工具所需要的格式。",
        code: "evtx_dump -o jsonl Security.evtx > security.jsonl",
      },
      {
        name: "evtx_dump 与本站的对比",
        body: "如需编写脚本、处理非常庞大的数据集合或同时处理多台主机，请使用 evtx_dump。如需临时排查，请使用浏览器版本：无需安装即可获得筛选、按 Event ID 的分布统计、时间线、内置检测以及 CSV、TXT、JSON 或 XML 导出。",
      },
    ],
    stepsHeading: "如何在浏览器中使用 evtx_dump",
    steps: [
      {
        title: "打开 EVTX parser",
        body: "打开主页。evtx crate 的 WebAssembly 构建会在 Web Worker 中加载。",
      },
      {
        title: "拖入您的 .evtx 文件",
        body: "将一个或多个 .evtx 文件拖到拖放区。它们会在本地逐条记录地解析，就像 evtx_dump 那样。",
      },
      {
        title: "查看或导出",
        body: "筛选并查看每个事件重建后的 XML，然后导出为 JSON、CSV、TXT 或 XML。",
      },
    ],
    faqHeading: "evtx_dump 常见问题",
    faq: [
      {
        q: "evtx_dump 是什么？",
        a: "evtx_dump 是随 Rust crate omerbenamram/evtx 一起提供的 CLI 工具。它读取 Windows .evtx 文件，并使用多线程将每条记录打印为 XML、JSON 或 JSON Lines。它采用 MIT/Apache 许可，可在 Windows、macOS 和 Linux 上运行。",
      },
      {
        q: "本站真的是与 evtx_dump 相同的解析器吗？",
        a: "是的。解析核心就是编译为 WebAssembly 的 evtx crate，因此记录会以相同的方式重建。区别仅在于界面：带筛选和导出功能的浏览器 UI，而不是命令行。",
      },
      {
        q: "evtx_dump 与 python-evtx、EvtxECmd 相比如何？",
        a: "evtx_dump（Rust）速度最快，输出 XML/JSON。python-evtx 在 Python 脚本中使用方便，但速度慢得多。EvtxECmd（Eric Zimmerman 出品）通过按 Event ID 的映射将事件规范化为 CSV/JSON，在以 Windows 为中心的 DFIR 工作流中很受欢迎。",
      },
      {
        q: "evtx_dump 能读取损坏或部分残缺的 EVTX 文件吗？",
        a: "它能容忍受损的数据块，并跳过无法解析的记录而不会中止。若要从未分配空间中雕刻恢复记录，请参阅我们关于恢复已删除 EVTX 记录的指南。",
      },
    ],
  },
};
