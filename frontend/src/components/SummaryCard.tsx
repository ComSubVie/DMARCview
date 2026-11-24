import type { ReactNode } from "react";
import type { Policy } from "../types";
import { Badge } from "./ui";

function emphasise(text: string): ReactNode[] {
  return text.split(/(\d[\d.,]*%?)/g).map((part, index) =>
    /^\d/.test(part) ? <strong key={index}>{part}</strong> : <span key={index}>{part}</span>,
  );
}

export function SummaryCard({
  sentences,
  failed,
  policy,
}: {
  sentences: string[];
  failed: number;
  policy: Policy | null;
}) {
  const severity = failed > 0 ? { tone: "bad" as const, label: "Attention" } : { tone: "good" as const, label: "Clean" };
  const [lead, ...rest] = sentences;
  const review =
    policy && policy.available
      ? policy.p === "reject"
        ? "Your published policy is p=reject — unauthenticated mail is already blocked."
        : policy.p === "quarantine"
          ? "Your published policy is p=quarantine — failing mail is filtered, not blocked."
          : "Your published policy is p=none — failing mail is still delivered."
      : "No published policy has been observed in these reports yet.";

  return (
    <section className="card summary-card">
      <div className="summary-top">
        <span className="summary-label">
          <span className="dot" />
          Plain-English summary
        </span>
        <Badge tone={severity.tone}>{severity.label}</Badge>
      </div>
      <h2>What changed this period</h2>
      <div className="summary-text">
        {lead ? <p>{emphasise(lead)}</p> : null}
        {rest.slice(0, 3).map((sentence) => (
          <p key={sentence}>{emphasise(sentence)}</p>
        ))}
      </div>
      <div className="review">
        <span className="rev-label">Review</span>
        <span>{review}</span>
      </div>
    </section>
  );
}
