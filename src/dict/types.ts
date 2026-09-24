export type Dict = {
  meta: {
    title: string;
    description: string;
    siteName: string;
  };
  home: {
    heading: string;
    headline: string;
    intro: string;
    featuredHeading: string;
    dropArea: string;
    privacyNote: string;
    statusReading: string;
    statusParsing: string;
    eventsLabel: string;
    filterPlaceholder: string;
    clearFilter: string;
    noMatches: string;
    topIds: string;
    exportCsv: string;
    exportJson: string;
    exportTxt: string;
    includeXml: string;
    exporting: string;
    clearTime: string;
    clearAll: string;
    clearFilters: string;
    removeFile: string;
    whatIsHeading: string;
    whatIsBody: string;
    whatIsMore: string;
  };
  /** "Where to find .evtx files" panel under the home-page drop zone.
   *  Paths themselves live in components/EvtxLocations.tsx (not translated).
   *  In `howTo` bullets, text wrapped in `backticks` renders as <code>. */
  fileLocation: {
    heading: string;
    intro: string;
    /** Label for the winevt\Logs folder row. */
    allChannels: string;
    /** OS qualifier, e.g. "Windows Vista / Server 2008+". */
    vistaPlus: string;
    archived: string;
    legacy: string;
    howToHeading: string;
    howTo: string[];
    readMore: string;
    copy: string;
    copied: string;
  };
  table: {
    record: string;
    time: string;
    level: string;
    eventId: string;
    name: string;
    summary: string;
    provider: string;
    channel: string;
    computer: string;
    source: string;
    viewDetails: string;
    closeDetails: string;
    eventData: string;
    noEventData: string;
    showRawXml: string;
    hideRawXml: string;
    prev: string;
    next: string;
  };
  levels: {
    critical: string;
    error: string;
    warning: string;
    info: string;
    verbose: string;
    unknown: string;
  };
  filter: {
    advanced: string;
    addCondition: string;
    addGroup: string;
    removeCondition: string;
    removeGroup: string;
    and: string;
    or: string;
    reset: string;
    matchCount: string;
    eventDataKey: string;
    eventDataKeyPlaceholder: string;
    valuePlaceholder: string;
    fields: {
      level: string;
      category: string;
      eventId: string;
      provider: string;
      channel: string;
      computer: string;
      file: string;
      eventName: string;
      timestamp: string;
      eventData: string;
    };
    ops: {
      contains: string;
      notContains: string;
      equals: string;
      notEquals: string;
      startsWith: string;
      regex: string;
      exists: string;
      empty: string;
      eq: string;
      neq: string;
      lt: string;
      lte: string;
      gt: string;
      gte: string;
      in: string;
      notIn: string;
      before: string;
      after: string;
      between: string;
    };
    categories: {
      security: string;
      system: string;
      sysmon: string;
      powershell: string;
      defender: string;
      appLocker: string;
      taskScheduler: string;
      rdpLocal: string;
      rdpRemote: string;
      rdpCore: string;
      wmiActivity: string;
      firewall: string;
      bits: string;
      smbServer: string;
      smbClient: string;
      wlan: string;
      other: string;
    };
  };
  faq: {
    heading: string;
    items: { q: string; a: string }[];
  };
  footer: {
    blog: string;
    builtWith: string;
  };
  notFound: {
    title: string;
    heading: string;
    description: string;
    backHome: string;
  };
  blog: {
    indexTitle: string;
    indexIntro: string;
    readMore: string;
    backToBlog: string;
    publishedOn: string;
    updatedOn: string;
    readingTime: string;
    prevPost: string;
    nextPost: string;
    relatedHeading: string;
    resourcesHeading: string;
    byLine: string;
  };
  eventIds: {
    title: string;
    intro: string;
    description: string;
    columnId: string;
    columnName: string;
    columnNotes: string;
  };
  glossary: {
    title: string;
    intro: string;
    description: string;
  };
  tools: {
    title: string;
    intro: string;
    description: string;
    columnTool: string;
    columnPlatform: string;
    columnUseCase: string;
    columnLicense: string;
  };
  breadcrumb: {
    home: string;
    label: string;
  };
  eventId: {
    title: string;
    intro: string;
    description: string;
    channelLabel: string;
    providerLabel: string;
    notesLabel: string;
    inDepthHeading: string;
    inDepthCta: string;
    microsoftLearnHeading: string;
    microsoftLearnCta: string;
    relatedHeading: string;
    notCoveredYet: string;
    notFoundTitle: string;
    notFoundDescription: string;
  };
  tags: {
    indexTitle: string;
    indexIntro: string;
    indexDescription: string;
    tagTitleTemplate: string;
    tagIntroTemplate: string;
    tagDescriptionTemplate: string;
    postsCount: string;
    tagsOnPost: string;
    labels: Record<string, string>;
  };
  toc: {
    heading: string;
  };
};
