import type { DashboardFilters } from "../types";
import { useEffect, useMemo, useState } from "react";
import {
  ALL_CITIES,
  ALL_CONTINENTS,
  ALL_COUNTRIES,
  ALL_GROUPS,
  ALL_SECTORS,
  ALL_SOURCES,
  citiesFor,
  continents,
  countriesFor,
  dateRanges,
  economicSectors,
  isoCodesForCountries,
  normalizeSelection,
  sourceModes,
  summarizeSelection
} from "../data/catalog";

interface FilterRailProps {
  filters: DashboardFilters;
  onChange: (filters: DashboardFilters) => void;
  threatGroupOptions: string[];
}

export function FilterRail({ filters, onChange, threatGroupOptions }: FilterRailProps) {
  const countries = countriesFor(filters.continents);
  const fallbackCities = useMemo(() => citiesFor(filters.countries), [filters.countries]);
  const [cities, setCities] = useState(fallbackCities);

  useEffect(() => {
    let cancelled = false;
    setCities(fallbackCities);
    const isoCodes = isoCodesForCountries(filters.countries);
    if (!isoCodes.length) return;

    import("country-state-city").then(({ City }) => {
      if (cancelled) return;
      const loadedCities = isoCodes.flatMap((isoCode) => City.getCitiesOfCountry(isoCode) ?? []).map((city) => city.name);
      setCities([ALL_CITIES, ...Array.from(new Set([...fallbackCities.slice(1), ...loadedCities])).slice(0, 1200)]);
    });

    return () => {
      cancelled = true;
    };
  }, [fallbackCities, filters.countries]);

  function patch(next: Partial<DashboardFilters>) {
    onChange({ ...filters, ...next });
  }

  return (
    <section className="filter-rail strategic" aria-label="Strategic dashboard filters">
      <MultiSelect
        label="Sectors"
        value={filters.sectors}
        options={economicSectors}
        allValue={ALL_SECTORS}
        summary={summarizeSelection(filters.sectors, ALL_SECTORS, "All sectors")}
        onChange={(sectors) => patch({ sectors })}
      />
      <MultiSelect
        label="Continents"
        value={filters.continents}
        options={continents}
        allValue={ALL_CONTINENTS}
        summary={summarizeSelection(filters.continents, ALL_CONTINENTS, "All continents")}
        onChange={(continentsSelection) => patch({ continents: continentsSelection, countries: [ALL_COUNTRIES], cities: [ALL_CITIES] })}
      />
      <MultiSelect
        label="Countries"
        value={filters.countries}
        options={countries}
        allValue={ALL_COUNTRIES}
        summary={summarizeSelection(filters.countries, ALL_COUNTRIES, "All countries")}
        onChange={(countriesSelection) => patch({ countries: countriesSelection, cities: [ALL_CITIES] })}
      />
      <MultiSelect
        label="Cities"
        value={filters.cities}
        options={cities}
        allValue={ALL_CITIES}
        summary={summarizeSelection(filters.cities, ALL_CITIES, "All cities")}
        onChange={(citiesSelection) => patch({ cities: citiesSelection })}
      />
      <MultiSelect
        label="Threat groups"
        value={filters.threatGroups}
        options={threatGroupOptions}
        allValue={ALL_GROUPS}
        summary={summarizeSelection(filters.threatGroups, ALL_GROUPS, "All groups")}
        onChange={(threatGroups) => patch({ threatGroups })}
      />
      <MultiSelect
        label="Sources"
        value={filters.sourceModes}
        options={sourceModes}
        allValue={ALL_SOURCES}
        summary={summarizeSelection(filters.sourceModes, ALL_SOURCES, "All sources")}
        onChange={(sourceModes) => patch({ sourceModes })}
      />
      <label className="filter-select range-select">
        <span>Range</span>
        <strong>{filters.dateRange}</strong>
        <select value={filters.dateRange} onChange={(event) => patch({ dateRange: event.target.value })}>
          {dateRanges.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
    </section>
  );
}

function MultiSelect({
  label,
  value,
  options,
  allValue,
  summary,
  onChange
}: {
  label: string;
  value: string[];
  options: string[];
  allValue: string;
  summary: string;
  onChange: (values: string[]) => void;
}) {
  return (
    <label className="filter-select multi-filter">
      <span>{label}</span>
      <strong>{summary}</strong>
      <select
        multiple
        value={value}
        onChange={(event) => {
          const selected = Array.from(event.currentTarget.selectedOptions, (option) => option.value);
          onChange(normalizeSelection(selected, allValue));
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}
