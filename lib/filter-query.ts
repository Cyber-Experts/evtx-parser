// Structured filter engine for the events table.
//
// A query is a tree of AND/OR groups whose leaves are conditions. Each
// condition targets one field (top-level row metadata, the derived
// event-name / category, or an arbitrary EventData key) with an operator
// chosen by the field's value type. The model is plain serialisable data so
// it can later be persisted/shared via URL; React owns the tree and rebuilds
// it immutably through the helpers below.

import type { EventRow } from "@/lib/evtx-client";
import { eventName, providerHint, type ProviderHint } from "@/lib/event-info";

// Minimal shape the evaluator needs from a row: the parsed metadata plus the
// source filename. IndexedRow (in EvtxUploader) is assignable to this.
export type FilterRow = EventRow & { _file: string };

export type FieldId =
  | "level"
  | "category"
  | "eventId"
  | "provider"
  | "channel"
  | "computer"
  | "file"
  | "eventName"
  | "timestamp"
  | "eventData";

export type FieldType = "enum" | "number" | "text" | "date";

export type TextOp =
  | "contains"
  | "notContains"
  | "equals"
  | "notEquals"
  | "startsWith"
  | "regex"
  | "exists"
  | "empty";
export type NumberOp = "eq" | "neq" | "lt" | "lte" | "gt" | "gte";
export type EnumOp = "in" | "notIn";
export type DateOp = "before" | "after" | "between";
export type Operator = TextOp | NumberOp | EnumOp | DateOp;

export const FIELD_META: Record<FieldId, { type: FieldType }> = {
  level: { type: "enum" },
  category: { type: "enum" },
  eventId: { type: "number" },
  provider: { type: "text" },
  channel: { type: "text" },
  computer: { type: "text" },
  file: { type: "text" },
  eventName: { type: "text" },
  timestamp: { type: "date" },
  eventData: { type: "text" },
};

export const FIELD_IDS: FieldId[] = Object.keys(FIELD_META) as FieldId[];

export const OPERATORS_BY_TYPE: Record<FieldType, Operator[]> = {
  text: [
    "contains",
    "notContains",
    "equals",
    "notEquals",
    "startsWith",
    "regex",
    "exists",
    "empty",
  ],
  number: ["eq", "neq", "lt", "lte", "gt", "gte"],
  enum: ["in", "notIn"],
  date: ["before", "after", "between"],
};

// `value`/`value2` hold scalar inputs (text needle, number, date bounds);
// `values` holds the multi-select set for enum fields; `key` names the
// EventData field. Keeping every slot a string keeps the tree serialisable.
export type Condition = {
  id: string;
  type: "condition";
  field: FieldId;
  key?: string;
  op: Operator;
  value: string;
  value2?: string;
  values?: string[];
};

export type Group = {
  id: string;
  type: "group";
  combinator: "and" | "or";
  children: Node[];
};

export type Node = Condition | Group;

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

function eventDataValue(
  pairs: [string, string][],
  key: string | undefined,
): string | null {
  if (!key) return null;
  const k = key.toLowerCase();
  for (const [pk, pv] of pairs) {
    if (pk.toLowerCase() === k) return pv;
  }
  return null;
}

// The row's value for a field as a string (or null when absent).
function fieldString(
  c: Condition,
  row: FilterRow,
  pairs: [string, string][],
): string | null {
  switch (c.field) {
    case "level":
      return row.level == null ? null : String(row.level);
    case "category":
      return providerHint(row.provider) as ProviderHint;
    case "eventId":
      return row.event_id == null ? null : String(row.event_id);
    case "provider":
      return row.provider ?? null;
    case "channel":
      return row.channel ?? null;
    case "computer":
      return row.computer ?? null;
    case "file":
      return row._file;
    case "eventName":
      return eventName(row.event_id, row.provider);
    case "timestamp":
      return row.timestamp;
    case "eventData":
      return eventDataValue(pairs, c.key);
  }
}

function evalText(op: TextOp, actual: string | null, value: string): boolean {
  if (op === "exists") return actual != null && actual !== "";
  if (op === "empty") return actual == null || actual === "";
  if (value === "") return true; // nothing typed yet → no constraint
  if (op === "regex") {
    try {
      return new RegExp(value, "i").test(actual ?? "");
    } catch {
      return true; // invalid regex while typing → don't filter anything out
    }
  }
  const a = (actual ?? "").toLowerCase();
  const v = value.toLowerCase();
  switch (op) {
    case "contains":
      return a.includes(v);
    case "notContains":
      return !a.includes(v);
    case "equals":
      return a === v;
    case "notEquals":
      return a !== v;
    case "startsWith":
      return a.startsWith(v);
  }
}

function evalNumber(op: NumberOp, actual: number | null, value: string): boolean {
  if (value.trim() === "") return true;
  const n = Number(value);
  if (Number.isNaN(n)) return true;
  if (actual == null) return false;
  switch (op) {
    case "eq":
      return actual === n;
    case "neq":
      return actual !== n;
    case "lt":
      return actual < n;
    case "lte":
      return actual <= n;
    case "gt":
      return actual > n;
    case "gte":
      return actual >= n;
  }
}

// datetime-local inputs carry no zone; the app renders timestamps in UTC, so
// treat a zone-less bound as UTC for consistency.
function parseBound(value: string): number {
  if (!value) return NaN;
  const hasZone = /[zZ]|[+-]\d\d:?\d\d$/.test(value);
  return Date.parse(hasZone ? value : `${value}Z`);
}

function evalDate(c: Condition, row: FilterRow): boolean {
  const t = Date.parse(row.timestamp);
  if (Number.isNaN(t)) return false;
  const from = parseBound(c.value);
  if (c.op === "before") return Number.isNaN(from) ? true : t < from;
  if (c.op === "after") return Number.isNaN(from) ? true : t >= from;
  // between
  const to = parseBound(c.value2 ?? "");
  if (!Number.isNaN(from) && t < from) return false;
  if (!Number.isNaN(to) && t > to) return false;
  return true;
}

function evalCondition(
  c: Condition,
  row: FilterRow,
  pairs: [string, string][],
): boolean {
  const type = FIELD_META[c.field].type;
  switch (type) {
    case "enum": {
      const set = c.values ?? [];
      if (set.length === 0) return true; // empty selection → no constraint
      const actual = fieldString(c, row, pairs);
      const member = actual != null && set.includes(actual);
      return c.op === "notIn" ? !member : member;
    }
    case "number":
      return evalNumber(
        c.op as NumberOp,
        c.field === "eventId" ? row.event_id : null,
        c.value,
      );
    case "date":
      return evalDate(c, row);
    case "text":
      return evalText(c.op as TextOp, fieldString(c, row, pairs), c.value);
  }
}

export function evaluateNode(
  node: Node,
  row: FilterRow,
  pairs: [string, string][],
): boolean {
  if (node.type === "condition") return evalCondition(node, row, pairs);
  if (node.children.length === 0) return true;
  return node.combinator === "and"
    ? node.children.every((c) => evaluateNode(c, row, pairs))
    : node.children.some((c) => evaluateNode(c, row, pairs));
}

// True when the tree holds at least one condition (otherwise it matches
// everything and callers can skip evaluation entirely).
export function hasConditions(node: Node): boolean {
  if (node.type === "condition") return true;
  return node.children.some(hasConditions);
}

// ---------------------------------------------------------------------------
// Immutable construction / editing
// ---------------------------------------------------------------------------

function genId(): string {
  return crypto.randomUUID();
}

export function newCondition(field: FieldId = "eventData"): Condition {
  return withField({ id: genId(), type: "condition", field, op: "contains", value: "" }, field);
}

export function newGroup(combinator: "and" | "or" = "and"): Group {
  return { id: genId(), type: "group", combinator, children: [] };
}

export function emptyRoot(): Group {
  return newGroup("and");
}

// Reset a condition's operator/value slots to valid defaults for a field,
// preserving its id (and the EventData key when staying on eventData).
export function withField(c: Condition, field: FieldId): Condition {
  const type = FIELD_META[field].type;
  return {
    id: c.id,
    type: "condition",
    field,
    op: OPERATORS_BY_TYPE[type][0],
    value: "",
    value2: undefined,
    values: type === "enum" ? [] : undefined,
    key: field === "eventData" ? (c.key ?? "") : undefined,
  };
}

export function addChild(root: Group, parentId: string, child: Node): Group {
  function rec(g: Group): Group {
    if (g.id === parentId) return { ...g, children: [...g.children, child] };
    return {
      ...g,
      children: g.children.map((c) => (c.type === "group" ? rec(c) : c)),
    };
  }
  return rec(root);
}

export function removeNode(root: Group, id: string): Group {
  function rec(g: Group): Group {
    return {
      ...g,
      children: g.children
        .filter((c) => c.id !== id)
        .map((c) => (c.type === "group" ? rec(c) : c)),
    };
  }
  return rec(root);
}

export function patchCondition(
  root: Group,
  id: string,
  patch: Partial<Condition>,
): Group {
  function rec(g: Group): Group {
    return {
      ...g,
      children: g.children.map((c) => {
        if (c.id === id && c.type === "condition") return { ...c, ...patch };
        if (c.type === "group") return rec(c);
        return c;
      }),
    };
  }
  return rec(root);
}

export function setCombinator(
  root: Group,
  id: string,
  combinator: "and" | "or",
): Group {
  function rec(g: Group): Group {
    const next = g.id === id ? { ...g, combinator } : g;
    return {
      ...next,
      children: next.children.map((c) => (c.type === "group" ? rec(c) : c)),
    };
  }
  return rec(root);
}
