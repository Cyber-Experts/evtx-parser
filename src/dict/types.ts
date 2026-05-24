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
    includeXml: string;
    exporting: string;
    clearTime: string;
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
