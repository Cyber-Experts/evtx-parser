// Rule pre-filter ("gates"). Every compiled rule carries a set of literal
// atoms such that at least one must hold whenever the rule matches — e.g.
// `Image|endswith: \certutil.exe` or `CommandLine|contains: urlcache`. For
// the rules that can apply to a (channel, Event ID) pair, the atoms are
// indexed by field: equality and prefix/suffix atoms as hash lookups, and
// substring atoms in one Aho–Corasick automaton per field. An event then
// only runs the full detection of rules whose gate fired, instead of every
// rule for its channel (≈1,200 for Sysmon process creation).

/** A necessary literal condition (value lower-cased; field null = keywords). */
export type Atom = {
  field: string | null;
  kind: "=" | "s" | "e" | "c";
  lit: string;
};

/** Multi-pattern substring search (lower-cased UTF-16 code units). */
export class AhoCorasick {
  private next: Map<number, number>[] = [new Map()];
  private fail: number[] = [0];
  private out: number[][] = [[]];

  constructor(patterns: string[]) {
    patterns.forEach((p, id) => {
      let s = 0;
      for (let i = 0; i < p.length; i++) {
        const c = p.charCodeAt(i);
        let n = this.next[s].get(c);
        if (n === undefined) {
          n = this.next.length;
          this.next.push(new Map());
          this.fail.push(0);
          this.out.push([]);
          this.next[s].set(c, n);
        }
        s = n;
      }
      this.out[s].push(id);
    });
    // BFS for failure links; outputs are merged along them.
    const queue: number[] = [];
    for (const n of this.next[0].values()) queue.push(n);
    for (let qi = 0; qi < queue.length; qi++) {
      const s = queue[qi];
      for (const [c, n] of this.next[s]) {
        queue.push(n);
        let f = this.fail[s];
        while (f && !this.next[f].has(c)) f = this.fail[f];
        const fn = this.next[f].get(c);
        this.fail[n] = fn !== undefined && fn !== n ? fn : 0;
        if (this.out[this.fail[n]].length) this.out[n] = this.out[n].concat(this.out[this.fail[n]]);
      }
    }
  }

  /** Call `hit(id)` for every pattern occurring in `text` (ids may repeat). */
  scan(text: string, hit: (id: number) => void): void {
    const next = this.next;
    const fail = this.fail;
    const out = this.out;
    let s = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      let n = next[s].get(c);
      while (n === undefined && s !== 0) {
        s = fail[s];
        n = next[s].get(c);
      }
      s = n ?? 0;
      const o = out[s];
      for (let k = 0; k < o.length; k++) hit(o[k]);
    }
  }
}

type FieldGroup<P> = {
  field: string | null;
  profile: P;
  eq: Map<string, number[]>;
  pre: [number, Map<string, number[]>][];
  suf: [number, Map<string, number[]>][];
  ac: AhoCorasick | null;
  acTargets: number[][];
};

function push<K>(m: Map<K, number[]>, k: K, v: number) {
  const a = m.get(k);
  if (a) a.push(v);
  else m.set(k, [v]);
}

/**
 * Gate index over a candidate list. `candidates[i]` is gated by `gates[i]`
 * (null = always evaluated) under `profiles[i]`.
 */
export class GateIndex<P> {
  readonly always: number[] = [];
  private groups: FieldGroup<P>[] = [];
  private mark: Uint32Array;
  private epoch = 0;

  constructor(gates: (Atom[] | null)[], profiles: P[]) {
    this.mark = new Uint32Array(gates.length);
    const byKey = new Map<string, { field: string | null; profile: P; atoms: [Atom, number][] }>();
    gates.forEach((g, i) => {
      if (!g) {
        this.always.push(i);
        return;
      }
      for (const a of g) {
        const key = `${a.field ?? "\u0000"}|${String(profiles[i])}`;
        let e = byKey.get(key);
        if (!e) byKey.set(key, (e = { field: a.field, profile: profiles[i], atoms: [] }));
        e.atoms.push([a, i]);
      }
    });
    for (const { field, profile, atoms } of byKey.values()) {
      const eq = new Map<string, number[]>();
      const pre = new Map<number, Map<string, number[]>>();
      const suf = new Map<number, Map<string, number[]>>();
      const contains = new Map<string, number[]>();
      for (const [a, i] of atoms) {
        if (a.kind === "=") push(eq, a.lit, i);
        else if (a.kind === "c") push(contains, a.lit, i);
        else {
          const m = a.kind === "s" ? pre : suf;
          let byLen = m.get(a.lit.length);
          if (!byLen) m.set(a.lit.length, (byLen = new Map()));
          push(byLen, a.lit, i);
        }
      }
      const lits = [...contains.keys()];
      this.groups.push({
        field,
        profile,
        eq,
        pre: [...pre].sort((a, b) => a[0] - b[0]),
        suf: [...suf].sort((a, b) => a[0] - b[0]),
        ac: lits.length ? new AhoCorasick(lits) : null,
        acTargets: lits.map((l) => contains.get(l) as number[]),
      });
    }
  }

  /**
   * Candidate positions whose gate fired for this event, plus the ungated
   * ones. `valueOf(null, …)` must return the keyword haystack.
   */
  select(valueOf: (field: string | null, profile: P) => string | undefined): number[] {
    const out = this.always.slice();
    if (++this.epoch === 0xffffffff) {
      this.mark.fill(0);
      this.epoch = 1;
    }
    const epoch = this.epoch;
    const mark = this.mark;
    const add = (list: number[] | undefined) => {
      if (!list) return;
      for (const i of list) {
        if (mark[i] !== epoch) {
          mark[i] = epoch;
          out.push(i);
        }
      }
    };
    for (const g of this.groups) {
      const v = valueOf(g.field, g.profile);
      if (v === undefined) continue;
      if (g.eq.size) add(g.eq.get(v));
      const n = v.length;
      for (const [len, m] of g.pre) {
        if (len > n) break;
        add(m.get(v.slice(0, len)));
      }
      for (const [len, m] of g.suf) {
        if (len > n) break;
        add(m.get(v.slice(n - len)));
      }
      if (g.ac) {
        const targets = g.acTargets;
        g.ac.scan(v, (id) => add(targets[id]));
      }
    }
    return out;
  }
}
