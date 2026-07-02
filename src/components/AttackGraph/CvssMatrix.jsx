import React from "react";

const METRICS = {
  AV: {
    label: "Vecteur d’accès",
    values: {
      L: { label: "Local", value: 0.395 },
      A: { label: "Réseau adjacent", value: 0.646 },
      N: { label: "Réseau", value: 1 },
    },
  },
  AC: {
    label: "Complexité",
    values: {
      H: { label: "Haute", value: 0.35 },
      M: { label: "Moyenne", value: 0.61 },
      L: { label: "Faible", value: 0.71 },
    },
  },
  Au: {
    label: "Authentification",
    values: {
      M: { label: "Multiple", value: 0.45 },
      S: { label: "Unique", value: 0.56 },
      N: { label: "Aucune", value: 0.704 },
    },
  },
  C: {
    label: "Confidentialité",
    values: {
      N: { label: "Aucun", value: 0 },
      P: { label: "Partiel", value: 0.275 },
      C: { label: "Complet", value: 0.66 },
    },
  },
  I: {
    label: "Intégrité",
    values: {
      N: { label: "Aucun", value: 0 },
      P: { label: "Partiel", value: 0.275 },
      C: { label: "Complet", value: 0.66 },
    },
  },
  A: {
    label: "Disponibilité",
    values: {
      N: { label: "Aucun", value: 0 },
      P: { label: "Partiel", value: 0.275 },
      C: { label: "Complet", value: 0.66 },
    },
  },
};

const round1 = (value) => Math.round(value * 10) / 10;
const fixed = (value) => value.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");

function calculateCvss(metrics) {
  const values = Object.fromEntries(
    Object.entries(metrics)
      .filter(([key]) => METRICS[key])
      .map(([key, code]) => [key, METRICS[key].values[code].value]),
  );

  const impact =
    10.41 * (1 - (1 - values.C) * (1 - values.I) * (1 - values.A));
  const exploitability = 20 * values.AV * values.AC * values.Au;
  const impactFactor = impact === 0 ? 0 : 1.176;
  const score = round1(
    ((0.6 * impact + 0.4 * exploitability - 1.5) * impactFactor),
  );

  return {
    values,
    impact,
    exploitability,
    impactFactor,
    score: Math.max(0, score),
  };
}

function getRating(score) {
  if (score >= 7) return { label: "Élevé", className: "is-high" };
  if (score >= 4) return { label: "Modéré", className: "is-medium" };
  if (score > 0) return { label: "Faible", className: "is-low" };
  return { label: "Nul", className: "is-none" };
}

function MatrixChart({ impact, exploitability, score }) {
  const plot = { x: 72, y: 26, width: 440, height: 224 };
  const pointX = plot.x + (exploitability / 10) * plot.width;
  const pointY = plot.y + plot.height - (impact / 10) * plot.height;

  return (
    <div className="cvss-chart-wrap">
      <svg
        className="cvss-chart"
        viewBox="0 0 560 315"
        role="img"
        aria-label={`Matrice CVSS : exploitabilité ${round1(exploitability)} sur 10, impact ${round1(impact)} sur 10`}
      >
        <defs>
          <linearGradient id="risk-surface" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor="#3ccf91" stopOpacity="0.15" />
            <stop offset="48%" stopColor="#f1bd55" stopOpacity="0.13" />
            <stop offset="100%" stopColor="#f05c6c" stopOpacity="0.2" />
          </linearGradient>
          <filter id="point-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect
          className="cvss-chart__surface"
          x={plot.x}
          y={plot.y}
          width={plot.width}
          height={plot.height}
          fill="url(#risk-surface)"
        />

        {[0, 2, 4, 6, 8, 10].map((tick) => {
          const x = plot.x + (tick / 10) * plot.width;
          const y = plot.y + plot.height - (tick / 10) * plot.height;
          return (
            <g key={tick}>
              <line className="cvss-chart__grid" x1={x} y1={plot.y} x2={x} y2={plot.y + plot.height} />
              <line className="cvss-chart__grid" x1={plot.x} y1={y} x2={plot.x + plot.width} y2={y} />
              <text className="cvss-chart__tick" x={x} y={plot.y + plot.height + 21} textAnchor="middle">{tick}</text>
              <text className="cvss-chart__tick" x={plot.x - 14} y={y + 4} textAnchor="end">{tick}</text>
            </g>
          );
        })}

        <line className="cvss-chart__crosshair" x1={pointX} y1={pointY} x2={pointX} y2={plot.y + plot.height} />
        <line className="cvss-chart__crosshair" x1={plot.x} y1={pointY} x2={pointX} y2={pointY} />
        <circle className="cvss-chart__pulse" cx={pointX} cy={pointY} r="19" />
        <circle className="cvss-chart__point" cx={pointX} cy={pointY} r="10" filter="url(#point-glow)" />
        <text className="cvss-chart__score" x={pointX} y={pointY + 4} textAnchor="middle">{score}</text>

        <text className="cvss-chart__axis" x={plot.x + plot.width / 2} y="300" textAnchor="middle">
          EXPLOITABILITÉ →
        </text>
        <text
          className="cvss-chart__axis"
          x="18"
          y={plot.y + plot.height / 2}
          textAnchor="middle"
          transform={`rotate(-90 18 ${plot.y + plot.height / 2})`}
        >
          IMPACT →
        </text>
      </svg>
    </div>
  );
}

export function CvssMatrix({ cvss }) {
  if (!cvss) {
    return (
      <div className="cvss-unavailable">
        <span>Score non calculable</span>
        <p>
          Le mécanisme de cette vulnérabilité n’est pas encore identifié. Un
          vecteur CVSS serait spéculatif et ne peut pas être calculé proprement.
        </p>
      </div>
    );
  }

  const calculation = calculateCvss(cvss);
  const rating = getRating(calculation.score);
  const vector = ["AV", "AC", "Au", "C", "I", "A"]
    .map((key) => `${key}:${cvss[key]}`)
    .join("/");

  return (
    <div className="cvss-matrix">
      {cvss.provisional && (
        <div className="cvss-provisional">
          Estimation provisoire — à confirmer après validation technique
        </div>
      )}

      <div className="cvss-overview">
        <div className={`cvss-score-card ${rating.className}`}>
          <span>Score de base</span>
          <strong>{calculation.score}</strong>
          <small>{rating.label}</small>
        </div>
        <div className="cvss-vector-card">
          <span>Vecteur CVSS v2</span>
          <code>{vector}</code>
          <p>Score intrinsèque de la vulnérabilité, hors chaîne d’attaque.</p>
        </div>
      </div>

      <MatrixChart
        impact={calculation.impact}
        exploitability={calculation.exploitability}
        score={calculation.score}
      />

      <div className="cvss-metrics">
        {["AV", "AC", "Au", "C", "I", "A"].map((key) => {
          const metric = METRICS[key];
          const selected = metric.values[cvss[key]];
          return (
            <div key={key} className="cvss-metric">
              <span>{key} · {metric.label}</span>
              <strong>{selected.label}</strong>
              <small>{fixed(selected.value)}</small>
            </div>
          );
        })}
      </div>

      <div className="cvss-calculation">
        <h4>Détail du calcul</h4>
        <div>
          <span>Impact</span>
          <code>
            10.41 × [1 − (1−{fixed(calculation.values.C)}) ×
            (1−{fixed(calculation.values.I)}) × (1−{fixed(calculation.values.A)})]
          </code>
          <strong>{round1(calculation.impact)}</strong>
        </div>
        <div>
          <span>Exploitabilité</span>
          <code>
            20 × {fixed(calculation.values.AV)} × {fixed(calculation.values.AC)} × {fixed(calculation.values.Au)}
          </code>
          <strong>{round1(calculation.exploitability)}</strong>
        </div>
        <div>
          <span>Score de base</span>
          <code>
            [(0.6 × {round1(calculation.impact)}) + (0.4 × {round1(calculation.exploitability)}) − 1.5] × {calculation.impactFactor}
          </code>
          <strong>{calculation.score}</strong>
        </div>
      </div>
    </div>
  );
}
