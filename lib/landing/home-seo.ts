import type { LocaleContent } from "./locale-content";

/**
 * Keyword-rich prose block rendered below the tool on the homepage. Targets the
 * "evtx viewer / evtx viewer online / open evtx file online" cluster that the
 * tool fits but did not previously address in body copy, and seeds internal
 * links into the new landing pages.
 */
export type HomeSeo = {
  heading: string;
  paragraphs: string[];
  linksIntro: string;
  links: { label: string; path: string }[];
};

export const HOME_SEO: LocaleContent<HomeSeo> = {
  en: {
    heading: "A free online EVTX viewer that runs in your browser",
    paragraphs: [
      "EVTX parser is an online EVTX viewer and Windows Event Log parser. Open a .evtx file — Security.evtx, System.evtx, Application.evtx, Sysmon or PowerShell channels — and read every record without Event Viewer, without installing anything, and without a Windows host.",
      "Parsing runs entirely client-side via a Rust parser compiled to WebAssembly, so your logs never leave the browser. Filter by Event ID, provider, channel or time, inspect the raw event XML, and export the results to CSV, JSON or XML in a couple of clicks. You can now open several .evtx files at once and triage them in one combined view.",
    ],
    linksIntro: "Keep reading:",
    links: [
      { label: "Convert EVTX to XML, JSON or CSV", path: "/evtx-to-xml" },
      { label: "Open Security.evtx", path: "/security-evtx" },
      { label: "Open System.evtx", path: "/system-evtx" },
      { label: "Windows Event ID reference", path: "/event-ids" },
      { label: "EVTX tools compared", path: "/tools" },
    ],
  },
  fr: {
    heading: "Une visionneuse EVTX en ligne et gratuite qui s'exécute dans votre navigateur",
    paragraphs: [
      "EVTX parser est une visionneuse EVTX en ligne et un analyseur de journaux d'événements Windows. Ouvrez un fichier .evtx — Security.evtx, System.evtx, Application.evtx, les canaux Sysmon ou PowerShell — et lisez chaque enregistrement sans Event Viewer, sans rien installer et sans machine Windows.",
      "L'analyse s'effectue entièrement côté client grâce à un analyseur Rust compilé en WebAssembly : vos journaux ne quittent jamais le navigateur. Filtrez par Event ID, fournisseur, canal ou horodatage, inspectez le XML brut des événements, et exportez les résultats en CSV, JSON ou XML en quelques clics. Vous pouvez désormais ouvrir plusieurs fichiers .evtx à la fois et les trier dans une vue unifiée.",
    ],
    linksIntro: "Pour aller plus loin :",
    links: [
      { label: "Convertir un EVTX en XML, JSON ou CSV", path: "/evtx-to-xml" },
      { label: "Ouvrir Security.evtx", path: "/security-evtx" },
      { label: "Ouvrir System.evtx", path: "/system-evtx" },
      { label: "Référence des Event ID Windows", path: "/event-ids" },
      { label: "Comparatif des outils EVTX", path: "/tools" },
    ],
  },
  de: {
    heading: "Ein kostenloser Online-EVTX-Viewer, der in Ihrem Browser läuft",
    paragraphs: [
      "EVTX parser ist ein Online-EVTX-Viewer und Parser für Windows-Ereignisprotokolle. Öffnen Sie eine .evtx-Datei — Security.evtx, System.evtx, Application.evtx, Sysmon- oder PowerShell-Kanäle — und lesen Sie jeden Datensatz ohne Event Viewer, ohne Installation und ohne Windows-Host.",
      "Das Parsen läuft vollständig clientseitig über einen in WebAssembly kompilierten Rust-Parser, sodass Ihre Protokolle den Browser nie verlassen. Filtern Sie nach Event ID, Anbieter, Kanal oder Zeit, untersuchen Sie das rohe Ereignis-XML und exportieren Sie die Ergebnisse mit wenigen Klicks nach CSV, JSON oder XML. Sie können jetzt mehrere .evtx-Dateien gleichzeitig öffnen und in einer kombinierten Ansicht triagieren.",
    ],
    linksIntro: "Weiterlesen:",
    links: [
      { label: "EVTX in XML, JSON oder CSV konvertieren", path: "/evtx-to-xml" },
      { label: "Security.evtx öffnen", path: "/security-evtx" },
      { label: "System.evtx öffnen", path: "/system-evtx" },
      { label: "Windows-Event-ID-Referenz", path: "/event-ids" },
      { label: "EVTX-Tools im Vergleich", path: "/tools" },
    ],
  },
  es: {
    heading: "Un visor de EVTX en línea y gratuito que se ejecuta en tu navegador",
    paragraphs: [
      "EVTX parser es un visor de EVTX en línea y un analizador de registros de eventos de Windows. Abre un archivo .evtx — Security.evtx, System.evtx, Application.evtx, los canales de Sysmon o PowerShell — y lee cada registro sin Event Viewer, sin instalar nada y sin un host Windows.",
      "El análisis se ejecuta íntegramente en el lado del cliente mediante un analizador Rust compilado a WebAssembly, por lo que tus registros nunca salen del navegador. Filtra por Event ID, proveedor, canal u hora, inspecciona el XML sin procesar de los eventos y exporta los resultados a CSV, JSON o XML con un par de clics. Ahora puedes abrir varios archivos .evtx a la vez y triarlos en una vista combinada.",
    ],
    linksIntro: "Sigue leyendo:",
    links: [
      { label: "Convertir EVTX a XML, JSON o CSV", path: "/evtx-to-xml" },
      { label: "Abrir Security.evtx", path: "/security-evtx" },
      { label: "Abrir System.evtx", path: "/system-evtx" },
      { label: "Referencia de Event ID de Windows", path: "/event-ids" },
      { label: "Herramientas EVTX comparadas", path: "/tools" },
    ],
  },
  it: {
    heading: "Un visualizzatore EVTX online e gratuito che gira nel tuo browser",
    paragraphs: [
      "EVTX parser è un visualizzatore EVTX online e un parser dei registri eventi di Windows. Apri un file .evtx — Security.evtx, System.evtx, Application.evtx, i canali Sysmon o PowerShell — e leggi ogni record senza Event Viewer, senza installare nulla e senza un host Windows.",
      "Il parsing avviene interamente lato client tramite un parser Rust compilato in WebAssembly, quindi i tuoi log non lasciano mai il browser. Filtra per Event ID, provider, canale o orario, ispeziona l'XML grezzo degli eventi ed esporta i risultati in CSV, JSON o XML con un paio di clic. Ora puoi aprire più file .evtx contemporaneamente e analizzarli in una vista combinata.",
    ],
    linksIntro: "Continua a leggere:",
    links: [
      { label: "Convertire EVTX in XML, JSON o CSV", path: "/evtx-to-xml" },
      { label: "Aprire Security.evtx", path: "/security-evtx" },
      { label: "Aprire System.evtx", path: "/system-evtx" },
      { label: "Riferimento degli Event ID di Windows", path: "/event-ids" },
      { label: "Strumenti EVTX a confronto", path: "/tools" },
    ],
  },
  pt: {
    heading: "Um visualizador de EVTX online e gratuito que roda no seu navegador",
    paragraphs: [
      "O EVTX parser é um visualizador de EVTX online e um analisador de logs de eventos do Windows. Abra um arquivo .evtx — Security.evtx, System.evtx, Application.evtx, canais do Sysmon ou do PowerShell — e leia cada registro sem o Event Viewer, sem instalar nada e sem um host Windows.",
      "A análise é executada inteiramente no lado do cliente por meio de um parser Rust compilado para WebAssembly, de modo que seus logs nunca saem do navegador. Filtre por Event ID, provedor, canal ou horário, inspecione o XML bruto dos eventos e exporte os resultados para CSV, JSON ou XML com alguns cliques. Agora você pode abrir vários arquivos .evtx ao mesmo tempo e triá-los em uma visão combinada.",
    ],
    linksIntro: "Continue lendo:",
    links: [
      { label: "Converter EVTX para XML, JSON ou CSV", path: "/evtx-to-xml" },
      { label: "Abrir Security.evtx", path: "/security-evtx" },
      { label: "Abrir System.evtx", path: "/system-evtx" },
      { label: "Referência de Event ID do Windows", path: "/event-ids" },
      { label: "Ferramentas EVTX comparadas", path: "/tools" },
    ],
  },
  ja: {
    heading: "ブラウザ上で動作する無料のオンラインEVTXビューア",
    paragraphs: [
      "EVTX parser は、オンラインのEVTXビューア兼Windowsイベントログ解析ツールです。.evtxファイル（Security.evtx、System.evtx、Application.evtx、Sysmon や PowerShell のチャネル）を開き、Event Viewer を使わず、何もインストールせず、Windows ホストも不要で、すべてのレコードを読めます。",
      "解析は WebAssembly にコンパイルされた Rust パーサーによって完全にクライアント側で実行されるため、ログがブラウザの外に出ることはありません。Event ID、プロバイダー、チャネル、時刻でフィルタリングし、イベントの生のXMLを確認して、数クリックで結果を CSV、JSON、XML にエクスポートできます。複数の .evtx ファイルを同時に開き、ひとつの統合ビューでトリアージできるようになりました。",
    ],
    linksIntro: "さらに読む：",
    links: [
      { label: "EVTX を XML、JSON、CSV に変換", path: "/evtx-to-xml" },
      { label: "Security.evtx を開く", path: "/security-evtx" },
      { label: "System.evtx を開く", path: "/system-evtx" },
      { label: "Windows Event ID リファレンス", path: "/event-ids" },
      { label: "EVTX ツール比較", path: "/tools" },
    ],
  },
  zh: {
    heading: "一款在浏览器中运行的免费在线 EVTX 查看器",
    paragraphs: [
      "EVTX parser 是一款在线 EVTX 查看器和 Windows 事件日志解析器。打开一个 .evtx 文件——Security.evtx、System.evtx、Application.evtx、Sysmon 或 PowerShell 通道——无需 Event Viewer、无需安装任何软件、也无需 Windows 主机即可读取每一条记录。",
      "解析完全在客户端通过编译为 WebAssembly 的 Rust 解析器运行，因此您的日志绝不会离开浏览器。按 Event ID、提供程序、通道或时间进行筛选，查看事件的原始 XML，并只需点击几下即可将结果导出为 CSV、JSON 或 XML。现在您可以一次打开多个 .evtx 文件，并在一个合并视图中进行分流。",
    ],
    linksIntro: "继续阅读：",
    links: [
      { label: "将 EVTX 转换为 XML、JSON 或 CSV", path: "/evtx-to-xml" },
      { label: "打开 Security.evtx", path: "/security-evtx" },
      { label: "打开 System.evtx", path: "/system-evtx" },
      { label: "Windows Event ID 参考", path: "/event-ids" },
      { label: "EVTX 工具对比", path: "/tools" },
    ],
  },
};
