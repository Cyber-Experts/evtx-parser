import type { Dict } from "./types";

export const pt: Dict = {
  meta: {
    title: "EVTX parser — forense de logs de eventos Windows no navegador",
    description:
      "Analise arquivos .evtx do Windows inteiramente no navegador. Forense em WebAssembly — os arquivos nunca saem do seu dispositivo.",
    siteName: "EVTX parser",
  },
  home: {
    heading: "EVTX parser",
    headline: "EVTX parser — visualizador de logs de eventos Windows no navegador",
    intro:
      "Solte um log de eventos .evtx do Windows. A análise roda inteiramente no navegador via WebAssembly — nada é enviado.",
    featuredHeading: "Guias em destaque",
    dropArea: "Solte o .evtx aqui ou clique para escolher",
    privacyNote: "Os arquivos ficam no seu dispositivo. Análise 100 % no cliente.",
    statusReading: "Lendo {name}…",
    statusParsing: "Analisando o log de eventos…",
    eventsLabel: "eventos",
    filterPlaceholder: "Filtrar por Event ID, provedor, canal, computador…",
    clearFilter: "Limpar",
    noMatches: "Nenhum evento corresponde ao filtro.",
    topIds: "IDs frequentes",
    exportCsv: "Exportar CSV",
    exportJson: "Exportar JSON",
    includeXml: "Coluna XML bruto",
    exporting: "Exportando…",
    clearTime: "Limpar intervalo",
  },
  table: {
    record: "Reg. #",
    time: "Hora (UTC)",
    level: "Nível",
    eventId: "Event ID",
    name: "Nome",
    summary: "Resumo",
    provider: "Provedor",
    channel: "Canal",
    computer: "Computador",
    viewDetails: "Detalhes",
    closeDetails: "Fechar",
    eventData: "Dados do evento",
    noEventData: "Este registro não tem campos EventData.",
    showRawXml: "Mostrar XML bruto",
    hideRawXml: "Ocultar XML bruto",
    prev: "ant.",
    next: "próx.",
  },
  levels: {
    critical: "Crítico",
    error: "Erro",
    warning: "Aviso",
    info: "Informação",
    verbose: "Detalhado",
    unknown: "—",
  },
  faq: {
    heading: "FAQ logs de eventos",
    items: [
      {
        q: "O que é um arquivo EVTX?",
        a: "EVTX é o formato binário do log de eventos do Windows introduzido no Windows Vista. Cada .evtx é uma sequência de blocos de 64 KB; cada bloco contém uma tabela de templates XML e um fluxo de registros que a referenciam. A análise reconstrói o XML completo de cada evento.",
      },
      {
        q: "Onde encontro .evtx no Windows?",
        a: "Os logs ativos ficam em C:\\Windows\\System32\\winevt\\Logs. Os três principais para forense são Security.evtx (logons, privilégios), System.evtx (drivers, serviços) e Application.evtx (erros de aplicação). Os canais Sysmon e PowerShell costumam ser os mais valiosos em resposta a incidentes.",
      },
      {
        q: "Esta ferramenta envia meu .evtx para algum lugar?",
        a: "Não. A análise acontece em um Web Worker usando um parser EVTX em Rust compilado para WebAssembly. O arquivo é lido na memória do navegador e nunca transmitido. Desligue a rede se quiser verificar.",
      },
      {
        q: "O que significa a coluna Nível?",
        a: "Os níveis EVTX são numéricos: 1 Crítico, 2 Erro, 3 Aviso, 4 Informação, 5 Detalhado. A Microsoft atribui alguns IDs conhecidos (ex.: Security 4625 = falha de autenticação no nível Informação) — só a severidade não basta para triagem.",
      },
      {
        q: "Aguenta arquivos .evtx muito grandes?",
        a: "A análise roda em um Web Worker. A memória escala com o tamanho; algumas centenas de MB são confortáveis em navegadores modernos. Para coleções maiores, exporte com evtx_dump e recarregue em partes.",
      },
    ],
  },
  footer: {
    blog: "Blog",
    builtWith:
      "Feito com WebAssembly e o crate Rust omerbenamram/evtx. 100 % no cliente — seus arquivos não saem do navegador.",
  },
  notFound: {
    title: "404 — página não encontrada",
    heading: "Página não encontrada",
    description:
      "Essa URL não existe neste site. Talvez tenha sido movida, ou você seguiu um link antigo.",
    backHome: "← Voltar ao início",
  },
  blog: {
    indexTitle: "Notas sobre logs de eventos",
    indexIntro:
      "Notas curtas sobre o formato binário do log de eventos do Windows, Event IDs úteis em forense e fluxos de triagem.",
    readMore: "Leia mais",
    backToBlog: "← Voltar ao blog",
    publishedOn: "Publicado",
    updatedOn: "Atualizado",
    readingTime: "{n} min de leitura",
    prevPost: "← Anterior",
    nextPost: "Próximo →",
    relatedHeading: "Posts relacionados",
    resourcesHeading: "Recursos externos",
    byLine: "Por",
  },
  eventIds: {
    title: "Referência de Event ID do Windows",
    intro:
      "Índice curado dos Event ID do Windows que importam em um caso forense — agrupados por canal, com os campos EventData mais úteis. IDs cobertos vão para o guia detalhado; os demais para o Microsoft Learn.",
    description:
      "Índice de referência dos Event ID do Windows úteis em DFIR: Security 4624/4625/1102, System 7045/7036, Sysmon 1/3/7/11, PowerShell 4104, TaskScheduler, Kerberos — com links para guias detalhados.",
    columnId: "Event ID",
    columnName: "Nome",
    columnNotes: "Notas",
  },
  glossary: {
    title: "Glossário do log de eventos do Windows",
    intro:
      "Os termos que aparecem nos registros .evtx e nos relatórios DFIR, explicados em uma ou duas frases.",
    description:
      "Definições claras dos termos do log de eventos do Windows: LogonType, BinXML, canal, provider, chunk, template, SID, EventData, RecordID etc.",
  },
  tools: {
    title: "Ferramentas EVTX comparadas: KAPE, FTK Imager, wevtutil, evtx_dump",
    intro:
      "Comparação lado a lado das ferramentas usadas por analistas com o log de eventos do Windows — para que cada uma é boa, quanto custa e onde falha.",
    description:
      "Compare KAPE, FTK Imager, wevtutil, evtx_dump, python-evtx, RawCopy e EVTX parser — por plataforma, caso de uso, licença e limitações.",
    columnTool: "Ferramenta",
    columnPlatform: "Plataforma",
    columnUseCase: "Caso de uso principal",
    columnLicense: "Licença",
  },
  breadcrumb: {
    home: "Início",
    label: "Trilha de migalhas",
  },
  eventId: {
    title: "Event ID {id}: {name} ({channel})",
    intro:
      "O que esse Event ID realmente registra em disco, os campos EventData a ler primeiro e onde ele se encaixa em um fluxo de triagem DFIR.",
    description:
      "Windows Event ID {id} ({name}) no canal {channel}: significado, campos EventData, técnicas ofensivas comuns e Event IDs relacionados.",
    channelLabel: "Canal",
    providerLabel: "Provedor",
    notesLabel: "Notas de triagem",
    inDepthHeading: "Guia detalhado",
    inDepthCta: "Ler a análise completa",
    microsoftLearnHeading: "Microsoft Learn",
    microsoftLearnCta: "Abrir a referência oficial",
    relatedHeading: "Event IDs relacionados",
    notCoveredYet:
      "Este Event ID está no índice mas ainda não tem uma análise detalhada. O Microsoft Learn cobre os campos no nível do protocolo.",
    notFoundTitle: "Event ID desconhecido",
    notFoundDescription:
      "Este Event ID ainda não consta no índice de referência.",
  },
  tags: {
    indexTitle: "Tópicos — todas as tags do blog",
    indexIntro:
      "Todos os tópicos cobertos no blog, com o número de posts por tag. Use como segunda camada de navegação ao lado do índice de Event ID.",
    indexDescription:
      "Navegue pelos tópicos do blog EVTX parser: auditoria Security, Sysmon, PowerShell, Kerberos, serviços, internos do formato EVTX e coleta forense.",
    tagTitleTemplate: "Posts com a tag «{tag}»",
    tagIntroTemplate:
      "Todos os posts do blog com a tag «{tag}», dos mais recentes primeiro.",
    tagDescriptionTemplate:
      "Posts de forense do log de eventos do Windows com a tag «{tag}» — notas DFIR, técnicas ofensivas e internos do parser.",
    postsCount: "{n} posts",
    tagsOnPost: "Tags",
    labels: {
      security: "Auditoria Security",
      logon: "Logon",
      process: "Processo",
      account: "Conta",
      privileges: "Privilégios",
      "object-access": "Acesso a objetos",
      kerberos: "Kerberos",
      "anti-forensics": "Anti-forense",
      attack: "Técnicas ofensivas",
      sysmon: "Sysmon",
      powershell: "PowerShell",
      system: "Canal System",
      service: "Serviço",
      persistence: "Persistência",
      format: "Formato EVTX",
      fundamentals: "Fundamentos",
      collection: "Coleta",
      tooling: "Ferramentas",
      navigation: "Navegação",
    },
  },
  toc: {
    heading: "Nesta página",
  },
};
