import { Globe2 } from "lucide-react";
import { formatNumber } from "../lib/format";
import type { Country } from "../types";
import { EmptyState } from "./ui";

export function CountriesCard({ countries }: { countries: Country[] }) {
  const rows = countries.filter((country) => country.messages > 0).slice(0, 6);
  const max = Math.max(1, ...rows.map((country) => country.messages));

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Top countries</h2>
          <p className="card-sub">By message volume</p>
        </div>
        <Globe2 size={16} color="#98a2b3" />
      </div>
      {rows.length === 0 ? (
        <EmptyState icon={<Globe2 size={20} />} title="No geography yet">
          Install a GeoIP database to map sending IPs to countries.
        </EmptyState>
      ) : (
        <div className="country-list">
          {rows.map((country) => {
            const alignedShare = country.messages > 0 ? country.aligned / country.messages : 1;
            return (
              <div className="country-row" key={country.code ?? "unknown"}>
                <span className="flag" aria-hidden="true">
                  {country.flag || "🌐"}
                </span>
                <span className="c-name">{country.name || "Unknown"}</span>
                <span className="c-value num">{formatNumber(country.messages)}</span>
                <div className="bar">
                  <span
                    className={alignedShare < 0.9 ? "risk" : ""}
                    style={{ width: `${Math.max(6, (country.messages / max) * 100)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
