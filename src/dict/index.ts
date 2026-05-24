import { de } from "./de";
import { en } from "./en";
import { es } from "./es";
import { fr } from "./fr";
import { it } from "./it";
import { ja } from "./ja";
import { pt } from "./pt";
import { zh } from "./zh";
import type { Locale } from "./locales";
import type { Dict } from "./types";

const dicts: Record<Locale, Dict> = { en, fr, es, de, it, pt, ja, zh };

export function getDict(locale: Locale): Dict {
  return dicts[locale];
}

export type { Dict } from "./types";
export {
  locales,
  defaultLocale,
  localeNames,
  isLocale,
  type Locale,
} from "./locales";
