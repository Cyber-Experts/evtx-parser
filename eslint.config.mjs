import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // Modern React renders raw apostrophes / quotes in text nodes without
      // issue. The rule exists to catch stuck JSX (`>` ending up as text),
      // not real prose punctuation, and it produces enough false positives
      // on long-form copy to be noise.
      "react/no-unescaped-entities": "off",
    },
  },
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Generated artifacts:
    "lib/evtx-wasm/**", // wasm-pack output
    "crates/**", // Rust source
  ]),
]);

export default eslintConfig;
