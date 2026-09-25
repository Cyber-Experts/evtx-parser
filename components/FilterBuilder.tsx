"use client";

import { CATEGORY_IDS } from "@/lib/event-info";
import {
  type Condition,
  type FieldId,
  FIELD_IDS,
  FIELD_META,
  type Group,
  type Node,
  type Operator,
  OPERATORS_BY_TYPE,
  addChild,
  newCondition,
  newGroup,
  patchCondition,
  removeNode,
  setCombinator,
  withField,
} from "@/lib/filter-query";
import type { Dict } from "@/src/dict/types";

// Distinct values harvested from the loaded events, used to populate the
// <datalist> suggestions on text inputs.
export type FilterFacets = {
  providers: string[];
  channels: string[];
  computers: string[];
  files: string[];
  eventNames: string[];
  eventDataKeys: string[];
  valuesForKey: (key: string) => string[];
};

type Mutators = {
  patch: (id: string, patch: Partial<Condition>) => void;
  remove: (id: string) => void;
  addCondition: (parentId: string) => void;
  addGroup: (parentId: string) => void;
  setComb: (id: string, combinator: "and" | "or") => void;
};

const LEVEL_VALUES: Array<{ value: string; key: keyof Dict["levels"] }> = [
  { value: "1", key: "critical" },
  { value: "2", key: "error" },
  { value: "3", key: "warning" },
  { value: "4", key: "info" },
  { value: "5", key: "verbose" },
];

const chipBase =
  "rounded border px-1.5 py-0.5 font-mono text-xs transition-colors";
const chipOn =
  "border-ink-900 bg-ink-900 text-ink-50 dark:border-ink-100 dark:bg-ink-100 dark:text-ink-900";
const chipOff =
  "border-ink-200 text-ink-500 hover:border-ink-400 dark:border-ink-800 dark:hover:border-ink-600";
const selectCls =
  "rounded-md border border-ink-300 bg-transparent px-2 py-1 text-xs outline-none focus:border-ink-500 dark:border-ink-700 dark:focus:border-ink-400";
const inputCls = `${selectCls} font-mono`;

function suggestionsFor(c: Condition, facets: FilterFacets): string[] {
  switch (c.field) {
    case "provider":
      return facets.providers;
    case "channel":
      return facets.channels;
    case "computer":
      return facets.computers;
    case "file":
      return facets.files;
    case "eventName":
      return facets.eventNames;
    case "eventData":
      return c.key ? facets.valuesForKey(c.key) : [];
    default:
      return [];
  }
}

function EnumValues({
  c,
  m,
  dict,
}: {
  c: Condition;
  m: Mutators;
  dict: Dict;
}) {
  const selected = new Set(c.values ?? []);
  const options =
    c.field === "level"
      ? LEVEL_VALUES.map((l) => ({ value: l.value, label: dict.levels[l.key] }))
      : CATEGORY_IDS.map((id) => ({
          value: id,
          label: dict.filter.categories[id],
        }));

  function toggle(value: string) {
    const next = new Set(selected);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    m.patch(c.id, { values: [...next] });
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const on = selected.has(o.value);
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => toggle(o.value)}
            aria-pressed={on}
            className={`${chipBase} ${on ? chipOn : chipOff}`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function ValueEditor({
  c,
  m,
  facets,
  dict,
}: {
  c: Condition;
  m: Mutators;
  facets: FilterFacets;
  dict: Dict;
}) {
  const type = FIELD_META[c.field].type;

  if (type === "enum") return <EnumValues c={c} m={m} dict={dict} />;

  if (type === "number")
    return (
      <input
        type="number"
        value={c.value}
        onChange={(e) => m.patch(c.id, { value: e.target.value })}
        placeholder={dict.filter.valuePlaceholder}
        className={`${inputCls} w-28`}
      />
    );

  if (type === "date") {
    if (c.op === "between")
      return (
        <div className="flex flex-wrap items-center gap-1.5">
          <input
            type="datetime-local"
            value={c.value}
            onChange={(e) => m.patch(c.id, { value: e.target.value })}
            className={inputCls}
          />
          <span className="text-ink-400">→</span>
          <input
            type="datetime-local"
            value={c.value2 ?? ""}
            onChange={(e) => m.patch(c.id, { value2: e.target.value })}
            className={inputCls}
          />
        </div>
      );
    return (
      <input
        type="datetime-local"
        value={c.value}
        onChange={(e) => m.patch(c.id, { value: e.target.value })}
        className={inputCls}
      />
    );
  }

  // text — exists/empty take no value
  if (c.op === "exists" || c.op === "empty") return null;

  const listId = `dl-${c.id}`;
  const suggestions = suggestionsFor(c, facets);
  return (
    <>
      <input
        type="text"
        value={c.value}
        onChange={(e) => m.patch(c.id, { value: e.target.value })}
        placeholder={dict.filter.valuePlaceholder}
        list={suggestions.length ? listId : undefined}
        className={`${inputCls} min-w-[10rem] flex-1`}
      />
      {suggestions.length > 0 && (
        <datalist id={listId}>
          {suggestions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      )}
    </>
  );
}

function ConditionRow({
  c,
  m,
  facets,
  dict,
}: {
  c: Condition;
  m: Mutators;
  facets: FilterFacets;
  dict: Dict;
}) {
  const type = FIELD_META[c.field].type;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <select
        value={c.field}
        onChange={(e) => m.patch(c.id, withField(c, e.target.value as FieldId))}
        className={selectCls}
        aria-label={dict.filter.fields.eventData}
      >
        {FIELD_IDS.map((f) => (
          <option key={f} value={f}>
            {dict.filter.fields[f]}
          </option>
        ))}
      </select>

      {c.field === "eventData" && (
        <input
          type="text"
          value={c.key ?? ""}
          onChange={(e) => m.patch(c.id, { key: e.target.value })}
          placeholder={dict.filter.eventDataKeyPlaceholder}
          list={`dlk-${c.id}`}
          className={`${inputCls} w-44`}
          aria-label={dict.filter.eventDataKey}
        />
      )}
      {c.field === "eventData" && (
        <datalist id={`dlk-${c.id}`}>
          {facets.eventDataKeys.map((k) => (
            <option key={k} value={k} />
          ))}
        </datalist>
      )}

      <select
        value={c.op}
        onChange={(e) => m.patch(c.id, { op: e.target.value as Operator })}
        className={selectCls}
        aria-label="operator"
      >
        {OPERATORS_BY_TYPE[type].map((op) => (
          <option key={op} value={op}>
            {dict.filter.ops[op]}
          </option>
        ))}
      </select>

      <ValueEditor c={c} m={m} facets={facets} dict={dict} />

      <button
        type="button"
        onClick={() => m.remove(c.id)}
        aria-label={dict.filter.removeCondition}
        title={dict.filter.removeCondition}
        className="ml-auto rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-500 hover:bg-ink-100 dark:border-ink-800 dark:hover:bg-ink-900"
      >
        ✕
      </button>
    </div>
  );
}

function GroupBox({
  g,
  m,
  facets,
  dict,
  isRoot,
}: {
  g: Group;
  m: Mutators;
  facets: FilterFacets;
  dict: Dict;
  isRoot: boolean;
}) {
  return (
    <div
      className={
        isRoot
          ? "flex flex-col gap-2"
          : "flex flex-col gap-2 rounded-md border border-ink-200 border-l-2 border-l-ink-300 p-2 dark:border-ink-800 dark:border-l-ink-600"
      }
    >
      <div className="flex items-center gap-1.5">
        <div className="inline-flex overflow-hidden rounded-md border border-ink-200 dark:border-ink-800">
          {(["and", "or"] as const).map((cb) => (
            <button
              key={cb}
              type="button"
              onClick={() => m.setComb(g.id, cb)}
              aria-pressed={g.combinator === cb}
              className={`px-2 py-1 text-xs font-medium transition-colors ${
                g.combinator === cb
                  ? "bg-ink-900 text-ink-50 dark:bg-ink-100 dark:text-ink-900"
                  : "text-ink-500 hover:bg-ink-100 dark:hover:bg-ink-900"
              }`}
            >
              {cb === "and" ? dict.filter.and : dict.filter.or}
            </button>
          ))}
        </div>
        {!isRoot && (
          <button
            type="button"
            onClick={() => m.remove(g.id)}
            aria-label={dict.filter.removeGroup}
            title={dict.filter.removeGroup}
            className="ml-auto rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-500 hover:bg-ink-100 dark:border-ink-800 dark:hover:bg-ink-900"
          >
            ✕
          </button>
        )}
      </div>

      {g.children.map((child: Node) =>
        child.type === "group" ? (
          <GroupBox
            key={child.id}
            g={child}
            m={m}
            facets={facets}
            dict={dict}
            isRoot={false}
          />
        ) : (
          <ConditionRow
            key={child.id}
            c={child}
            m={m}
            facets={facets}
            dict={dict}
          />
        ),
      )}

      <div className="flex gap-1.5">
        <button
          type="button"
          onClick={() => m.addCondition(g.id)}
          className="rounded-md border border-ink-300 px-2 py-1 text-xs text-ink-600 hover:bg-ink-100 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
        >
          + {dict.filter.addCondition}
        </button>
        <button
          type="button"
          onClick={() => m.addGroup(g.id)}
          className="rounded-md border border-ink-300 px-2 py-1 text-xs text-ink-600 hover:bg-ink-100 dark:border-ink-700 dark:text-ink-300 dark:hover:bg-ink-900"
        >
          + {dict.filter.addGroup}
        </button>
      </div>
    </div>
  );
}

export function FilterBuilder({
  query,
  onChange,
  facets,
  dict,
}: {
  query: Group;
  onChange: (next: Group) => void;
  facets: FilterFacets;
  dict: Dict;
}) {
  const m: Mutators = {
    patch: (id, patch) => onChange(patchCondition(query, id, patch)),
    remove: (id) => onChange(removeNode(query, id)),
    addCondition: (parentId) =>
      onChange(addChild(query, parentId, newCondition())),
    addGroup: (parentId) => onChange(addChild(query, parentId, newGroup("and"))),
    setComb: (id, combinator) => onChange(setCombinator(query, id, combinator)),
  };

  return <GroupBox g={query} m={m} facets={facets} dict={dict} isRoot />;
}
