import worldCountries from "world-countries";
import type { DashboardFilters, LanguageMode, MitreGroup } from "../types";

export const ALL_SECTORS = "All sectors";
export const ALL_CONTINENTS = "All continents";
export const ALL_COUNTRIES = "All countries";
export const ALL_CITIES = "All cities";
export const ALL_GROUPS = "All groups";
export const ALL_SOURCES = "All sources";

export const economicSectors = [
  ALL_SECTORS,
  "Agriculture, forestry and fishing",
  "Mining and quarrying",
  "Manufacturing",
  "Electricity, gas, steam and air conditioning supply",
  "Water supply, sewerage, waste management and remediation",
  "Construction",
  "Wholesale and retail trade; repair of motor vehicles and motorcycles",
  "Transportation and storage",
  "Accommodation and food service activities",
  "Information and communication",
  "Financial and insurance activities",
  "Real estate activities",
  "Professional, scientific and technical activities",
  "Administrative and support service activities",
  "Public administration and defence; compulsory social security",
  "Education",
  "Human health and social work activities",
  "Arts, entertainment and recreation",
  "Other service activities",
  "Activities of households as employers",
  "Activities of extraterritorial organizations and bodies"
];

const sectorLabelsEs: Record<string, string> = {
  [ALL_SECTORS]: "Todos los sectores",
  "Agriculture, forestry and fishing": "Agricultura, silvicultura y pesca",
  "Mining and quarrying": "Explotación de minas y canteras",
  Manufacturing: "Industrias manufactureras",
  "Electricity, gas, steam and air conditioning supply": "Suministro de electricidad, gas, vapor y aire acondicionado",
  "Water supply, sewerage, waste management and remediation": "Agua, saneamiento, residuos y remediación",
  Construction: "Construcción",
  "Wholesale and retail trade; repair of motor vehicles and motorcycles": "Comercio y reparación de vehículos y motocicletas",
  "Transportation and storage": "Transporte y almacenamiento",
  "Accommodation and food service activities": "Alojamiento y servicios de comida",
  "Information and communication": "Información y comunicaciones",
  "Financial and insurance activities": "Actividades financieras y de seguros",
  "Real estate activities": "Actividades inmobiliarias",
  "Professional, scientific and technical activities": "Actividades profesionales, científicas y técnicas",
  "Administrative and support service activities": "Servicios administrativos y de apoyo",
  "Public administration and defence; compulsory social security": "Administración pública, defensa y seguridad social",
  Education: "Educación",
  "Human health and social work activities": "Salud humana y asistencia social",
  "Arts, entertainment and recreation": "Artes, entretenimiento y recreación",
  "Other service activities": "Otras actividades de servicios",
  "Activities of households as employers": "Actividades de los hogares como empleadores",
  "Activities of extraterritorial organizations and bodies": "Organizaciones y organismos extraterritoriales"
};

type CountryRecord = {
  name: string;
  isoCode: string;
  continent: string;
  capital: string;
};

const countryRecords: CountryRecord[] = worldCountries
  .map((country) => ({
    name: country.name.common,
    isoCode: country.cca2,
    continent: continentFor(country.region, country.subregion),
    capital: country.capital?.[0] ?? ""
  }))
  .filter((country) => Boolean(country.name && country.isoCode && country.continent))
  .sort((left, right) => left.name.localeCompare(right.name));

export const continents = [
  ALL_CONTINENTS,
  "Africa",
  "Asia",
  "Europe",
  "North America",
  "Oceania",
  "South America"
];

export const fallbackThreatGroups = [
  ALL_GROUPS,
  "APT29",
  "APT28",
  "Lazarus Group",
  "APT41",
  "FIN7",
  "Scattered Spider",
  "LockBit",
  "BlackCat / ALPHV",
  "Cl0p",
  "MuddyWater",
  "Kimsuky",
  "Volt Typhoon",
  "Sandworm Team",
  "Turla",
  "OilRig",
  "ransomware",
  "cybercrime",
  "brand_impersonation",
  "account_takeover",
  "unknown"
];

export const sourceModes = [ALL_SOURCES, "Real only", "SOCMINT", "News/RSS", "Vulnerability", "Dark web authorized"];
export const dateRanges = ["24h", "7d", "30d", "90d", "365d"];

export const defaultDashboardFilters: DashboardFilters = {
  sectors: [ALL_SECTORS],
  continents: [ALL_CONTINENTS],
  countries: [ALL_COUNTRIES],
  cities: [ALL_CITIES],
  threatGroups: [ALL_GROUPS],
  sourceModes: [ALL_SOURCES],
  dateRange: "30d"
};

export function threatGroupOptions(groups: MitreGroup[]): string[] {
  const fromMitre = groups.flatMap((group) => [group.name, ...group.aliases]).filter(Boolean);
  return unique([ALL_GROUPS, ...fromMitre, ...fallbackThreatGroups.filter((group) => group !== ALL_GROUPS)]).slice(0, 260);
}

export function countriesFor(continentsSelection: string[]): string[] {
  const selected = selectedWithoutAll(continentsSelection, ALL_CONTINENTS);
  const countries =
    selected.length === 0
      ? countryRecords
      : countryRecords.filter((country) => selected.includes(country.continent));
  return [ALL_COUNTRIES, ...unique(countries.map((country) => country.name))];
}

export function citiesFor(countriesSelection: string[]): string[] {
  const selectedCountries = selectedWithoutAll(countriesSelection, ALL_COUNTRIES);
  if (!selectedCountries.length) return [ALL_CITIES];
  const cityNames = countryRecords.filter((country) => selectedCountries.includes(country.name)).map((country) => country.capital).filter(Boolean);
  return [ALL_CITIES, ...unique(cityNames)];
}

export function isoCodesForCountries(countriesSelection: string[]): string[] {
  const selectedCountries = selectedWithoutAll(countriesSelection, ALL_COUNTRIES);
  return countryRecords.filter((country) => selectedCountries.includes(country.name)).map((country) => country.isoCode);
}

export function localizedSectorLabel(value: string, language: LanguageMode): string {
  return language === "es" ? sectorLabelsEs[value] ?? value : value;
}

export function localizedCountryLabel(value: string, language: LanguageMode): string {
  if (value === ALL_COUNTRIES) return language === "es" ? "Todos los países" : value;
  if (language === "en") return value;
  const isoCode = countryRecords.find((country) => country.name === value)?.isoCode;
  if (!isoCode) return value;
  try {
    return new Intl.DisplayNames(["es"], { type: "region" }).of(isoCode) ?? value;
  } catch {
    return value;
  }
}

export function selectedWithoutAll(values: string[], allValue: string): string[] {
  return values.filter((value) => value !== allValue);
}

export function includesAll(values: string[], allValue: string): boolean {
  return values.length === 0 || values.includes(allValue);
}

export function normalizeSelection(values: string[], allValue: string): string[] {
  const next = unique(values).filter(Boolean);
  if (!next.length || next.includes(allValue)) return [allValue];
  return next;
}

export function summarizeSelection(values: string[], allValue: string, plural: string): string {
  if (includesAll(values, allValue)) return plural;
  if (values.length === 1) return values[0];
  return `${values.length} selected`;
}

function continentFor(region: string, subregion?: string): string {
  if (region === "Africa") return "Africa";
  if (region === "Asia") return "Asia";
  if (region === "Europe") return "Europe";
  if (region === "Oceania") return "Oceania";
  if (subregion === "South America") return "South America";
  if (region === "Americas") return "North America";
  return "";
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}
