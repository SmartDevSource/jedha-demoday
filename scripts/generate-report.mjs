import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { vulnerabilities } from "../src/components/AttackGraph/graphData.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outputDirectory = join(root, "reports");
const outputFile = join(outputDirectory, "EvilCorp_Rapport_Audit.html");
const publicDirectory = join(root, "public");
const publicFile = join(publicDirectory, "EvilCorp_Rapport_Audit.html");
const graphImage = await readFile(join(root, "project_graph_simple.png"));
const graphDataUri = `data:image/png;base64,${graphImage.toString("base64")}`;

const cvssMetrics = {
  AV: {
    label: "Vecteur d’accès",
    values: {
      L: ["Local", 0.395],
      A: ["Réseau adjacent", 0.646],
      N: ["Réseau", 1],
    },
  },
  AC: {
    label: "Complexité d’accès",
    values: {
      H: ["Haute", 0.35],
      M: ["Moyenne", 0.61],
      L: ["Faible", 0.71],
    },
  },
  Au: {
    label: "Authentification",
    values: {
      M: ["Multiple", 0.45],
      S: ["Unique", 0.56],
      N: ["Aucune", 0.704],
    },
  },
  C: {
    label: "Confidentialité",
    values: {
      N: ["Aucun", 0],
      P: ["Partiel", 0.275],
      C: ["Complet", 0.66],
    },
  },
  I: {
    label: "Intégrité",
    values: {
      N: ["Aucun", 0],
      P: ["Partiel", 0.275],
      C: ["Complet", 0.66],
    },
  },
  A: {
    label: "Disponibilité",
    values: {
      N: ["Aucun", 0],
      P: ["Partiel", 0.275],
      C: ["Complet", 0.66],
    },
  },
};

const paths = {
  "vuln-01": "Kali → User W / www-data",
  "vuln-02": "Kali → User J / John",
  "vuln-03": "Kali → User A / Alice",
  "vuln-04": "Kali → User B / Bob",
  "vuln-05": "User W / www-data → User J / John",
  "vuln-06": "User J / John → User R / Root",
  "vuln-07": "User A / Alice → User R / Root",
  "vuln-08": "User B / Bob → User R / Root",
  "vuln-09": "Kali → User R / Root",
};

const prerequisites = {
  "vuln-01": "Accès réseau à l’application PINGOZAURUS",
  "vuln-02": "Accès réseau au service SSH — validation encore requise",
  "vuln-03": "Accès réseau au service FTP",
  "vuln-04": "Accès réseau à EvilCorp Web sur le port 8081",
  "vuln-05": "Shell www-data obtenu via VULN-01",
  "vuln-06": "Compte John obtenu via VULN-05 ou VULN-02",
  "vuln-07": "Compte Alice obtenu via VULN-03",
  "vuln-08": "Compte Bob obtenu via VULN-04",
  "vuln-09": "Non déterminé",
};

const cvssRationales = {
  "vuln-01":
    "Exploitation distante, faible complexité, sans authentification. Les impacts restent partiels car le premier shell obtenu est limité à www-data.",
  "vuln-02":
    "Estimation provisoire : attaque distante, faible complexité et sans authentification préalable. Les impacts correspondent à la compromission du compte John.",
  "vuln-03":
    "La clé est récupérable à distance sans authentification forte. L’accès Alice entraîne des impacts partiels sur les trois propriétés de sécurité.",
  "vuln-04":
    "Injection exploitable à distance sans authentification. L’accès à Bob affecte la confidentialité et l’intégrité, sans effet direct démontré sur la disponibilité.",
  "vuln-05":
    "Dans le contexte du TP, la cible est considérée comme distante. Une authentification préalable sous www-data est requise avant la lecture du secret de John.",
  "vuln-06":
    "Dans le contexte du TP, l’accès est traité comme réseau. Un compte John est requis, puis l’exploitation mène à une compromission complète de Root.",
  "vuln-07":
    "Dans le contexte du TP, l’accès est traité comme réseau. Une session Alice est requise, puis la règle sudo permet une compromission complète.",
  "vuln-08":
    "Dans le contexte du TP, l’accès est traité comme réseau. Une session Bob est requise, puis le binaire SUID permet une compromission complète.",
  "vuln-09":
    "Aucun vecteur ne peut être attribué avant l’identification du mécanisme d’exploitation.",
};

const escapeHtml = (value = "") =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

const formatNumber = (value) =>
  Number(value.toFixed(3)).toString().replace(".", ",");

const round1 = (value) => Math.round(value * 10) / 10;

function calculateCvss(metrics) {
  if (!metrics) return null;
  const coefficients = Object.fromEntries(
    Object.keys(cvssMetrics).map((key) => [
      key,
      cvssMetrics[key].values[metrics[key]][1],
    ]),
  );
  const impact =
    10.41 *
    (1 -
      (1 - coefficients.C) *
        (1 - coefficients.I) *
        (1 - coefficients.A));
  const exploitability =
    20 * coefficients.AV * coefficients.AC * coefficients.Au;
  const factor = impact === 0 ? 0 : 1.176;
  const base = Math.max(
    0,
    round1((0.6 * impact + 0.4 * exploitability - 1.5) * factor),
  );
  return { coefficients, impact, exploitability, factor, base };
}

function riskLabel(score) {
  if (score === null) return "Non calculable";
  if (score >= 7) return "Élevé";
  if (score >= 4) return "Modéré";
  if (score > 0) return "Faible";
  return "Nul";
}

function riskClass(score) {
  if (score === null) return "risk-na";
  if (score >= 7) return "risk-high";
  if (score >= 4) return "risk-medium";
  if (score > 0) return "risk-low";
  return "risk-none";
}

function vectorString(cvss) {
  if (!cvss) return "Non disponible";
  return ["AV", "AC", "Au", "C", "I", "A"]
    .map((key) => `${key}:${cvss[key]}`)
    .join("/");
}

function riskMatrix(calculation) {
  if (!calculation) {
    return `
      <div class="matrix-unavailable">
        <strong>Matrice non calculable</strong>
        <p>Le mécanisme de VULN-09 n’est pas identifié. Positionner cette vulnérabilité dans la matrice créerait un résultat spéculatif.</p>
      </div>`;
  }

  const ticks = [10, 8, 6, 4, 2, 0];
  const nearestX = ticks.reduce((best, current) =>
    Math.abs(current - calculation.exploitability) <
    Math.abs(best - calculation.exploitability)
      ? current
      : best,
  );
  const nearestY = ticks.reduce((best, current) =>
    Math.abs(current - calculation.impact) <
    Math.abs(best - calculation.impact)
      ? current
      : best,
  );

  const rows = ticks
    .map((impact) => {
      const cells = ticks
        .slice()
        .reverse()
        .map((exploitability) => {
          const combined = (impact + exploitability) / 2;
          const cellClass =
            combined >= 7
              ? "matrix-high"
              : combined >= 4
                ? "matrix-medium"
                : "matrix-low";
          const marker =
            impact === nearestY && exploitability === nearestX
              ? `<span class="matrix-point">${calculation.base}</span>`
              : "";
          return `<td class="${cellClass}">${marker}</td>`;
        })
        .join("");
      return `<tr><th>${impact}</th>${cells}</tr>`;
    })
    .join("");

  return `
    <table class="risk-matrix">
      <caption>Matrice Impact × Exploitabilité</caption>
      <thead>
        <tr><th>Impact ↑</th><th>0</th><th>2</th><th>4</th><th>6</th><th>8</th><th>10</th></tr>
      </thead>
      <tbody>${rows}</tbody>
      <tfoot><tr><th></th><th colspan="6">Exploitabilité →</th></tr></tfoot>
    </table>`;
}

function metricTable(vulnerability, calculation) {
  if (!vulnerability.cvss || !calculation) return "";
  const rows = ["AV", "AC", "Au", "C", "I", "A"]
    .map((key) => {
      const metric = cvssMetrics[key];
      const [label, coefficient] = metric.values[vulnerability.cvss[key]];
      return `
        <tr>
          <td><strong>${key}</strong></td>
          <td>${metric.label}</td>
          <td>${label}</td>
          <td>${formatNumber(coefficient)}</td>
        </tr>`;
    })
    .join("");

  return `
    <table class="metrics-table">
      <thead><tr><th>Code</th><th>Métrique</th><th>Valeur</th><th>Coefficient</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function calculationBlock(vulnerability, calculation) {
  if (!calculation) return "";
  const c = calculation.coefficients;
  return `
    <div class="calculation">
      <p><strong>Impact</strong><br>
      <code>10,41 × [1 − (1−${formatNumber(c.C)}) × (1−${formatNumber(c.I)}) × (1−${formatNumber(c.A)})]</code>
      <span>= ${formatNumber(round1(calculation.impact))}</span></p>
      <p><strong>Exploitabilité</strong><br>
      <code>20 × ${formatNumber(c.AV)} × ${formatNumber(c.AC)} × ${formatNumber(c.Au)}</code>
      <span>= ${formatNumber(round1(calculation.exploitability))}</span></p>
      <p><strong>Score de base</strong><br>
      <code>[(0,6 × ${formatNumber(round1(calculation.impact))}) + (0,4 × ${formatNumber(round1(calculation.exploitability))}) − 1,5] × ${formatNumber(calculation.factor)}</code>
      <span>= ${formatNumber(calculation.base)} / 10</span></p>
    </div>`;
}

function vulnerabilitySection(vulnerability, index) {
  const calculation = calculateCvss(vulnerability.cvss);
  const score = calculation?.base ?? null;
  const provisional = vulnerability.cvss?.provisional
    ? `<div class="notice warning"><strong>Scoring provisoire.</strong> La méthode Hydra doit être reproduite avant de confirmer VULN-02.</div>`
    : "";
  const unconfirmed =
    vulnerability.status === "Non confirmée" && !vulnerability.cvss
      ? `<div class="notice muted"><strong>Vulnérabilité non trouvée.</strong> Aucun mécanisme ni score CVSS ne doit être inventé.</div>`
      : "";

  return `
    <section id="${vulnerability.id}" class="vulnerability page-break">
      <div class="section-tag">FICHE ${String(index + 1).padStart(2, "0")} · ${escapeHtml(vulnerability.label.toUpperCase())}</div>
      <h2>${escapeHtml(vulnerability.label.toUpperCase())} — ${escapeHtml(vulnerability.title)}</h2>
      <table class="identity-table">
        <tr>
          <th>Criticité audit</th><td>${escapeHtml(vulnerability.severity)}</td>
          <th>Statut</th><td>${escapeHtml(vulnerability.status)}</td>
        </tr>
        <tr>
          <th>Chemin du schéma</th><td>${escapeHtml(paths[vulnerability.id])}</td>
          <th>Service</th><td>${escapeHtml(vulnerability.service)}</td>
        </tr>
        <tr>
          <th>Prérequis</th><td>${escapeHtml(prerequisites[vulnerability.id])}</td>
          <th>Compte obtenu</th><td>${escapeHtml(vulnerability.obtainedUser)}</td>
        </tr>
      </table>
      ${provisional}${unconfirmed}

      <h3>Description technique</h3>
      <p>${escapeHtml(vulnerability.description)}</p>

      <h3>Preuve d’exploitation</h3>
      <pre>${escapeHtml(vulnerability.proof)}</pre>

      <h3>Impact</h3>
      <p>${escapeHtml(vulnerability.impact)}</p>

      <h3>Recommandations</h3>
      <ul>${vulnerability.recommendations
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul>

      <div class="cvss-block">
        <div class="cvss-heading">
          <div>
            <span>ÉVALUATION DU RISQUE</span>
            <h3>CVSS v2 — score de base</h3>
          </div>
          <div class="score ${riskClass(score)}">
            <strong>${score === null ? "N/A" : formatNumber(score)}</strong>
            <small>${riskLabel(score)}</small>
          </div>
        </div>
        <p class="vector"><strong>Vecteur :</strong> <code>${escapeHtml(vectorString(vulnerability.cvss))}</code></p>
        <p class="rationale">${escapeHtml(cvssRationales[vulnerability.id])}</p>
        <div class="matrix-layout">
          <div>${riskMatrix(calculation)}</div>
          <div>${metricTable(vulnerability, calculation)}</div>
        </div>
        ${calculationBlock(vulnerability, calculation)}
      </div>
    </section>`;
}

const scoredVulnerabilities = vulnerabilities.map((vulnerability) => ({
  ...vulnerability,
  calculation: calculateCvss(vulnerability.cvss),
}));

const summaryRows = scoredVulnerabilities
  .map((vulnerability) => {
    const score = vulnerability.calculation?.base ?? null;
    return `
      <tr>
        <td><strong>${escapeHtml(vulnerability.label.toUpperCase())}</strong></td>
        <td>${escapeHtml(vulnerability.title)}</td>
        <td>${escapeHtml(paths[vulnerability.id])}</td>
        <td>${score === null ? "N/A" : formatNumber(score)}</td>
        <td class="${riskClass(score)}">${riskLabel(score)}</td>
        <td>${escapeHtml(vulnerability.status)}</td>
      </tr>`;
  })
  .join("");

const html = `<!doctype html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Rapport d’audit EvilCorp</title>
  <style>
    @page { size: A4; margin: 16mm 15mm 17mm; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: #172b35;
      background: #ffffff;
      font-family: "Liberation Sans", Arial, sans-serif;
      font-size: 10.5pt;
      line-height: 1.48;
    }
    @media screen {
      html {
        min-height: 100%;
        background: #e8eef0;
      }
      body {
        width: min(1280px, 100%);
        min-height: 100vh;
        margin: 0 auto;
        box-shadow: 0 0 60px rgba(17, 43, 54, 0.14);
      }
      body > section:not(.cover) {
        padding: 48px clamp(32px, 5vw, 72px) 58px;
        background: #ffffff;
      }
      .report-nav {
        position: sticky;
        z-index: 50;
        top: 0;
        display: flex;
        align-items: center;
        gap: 4px;
        min-height: 58px;
        padding: 8px clamp(18px, 3vw, 38px);
        overflow-x: auto;
        color: #b9cbd1;
        background: rgba(7, 25, 37, 0.97);
        border-bottom: 1px solid #254651;
        box-shadow: 0 8px 24px rgba(7, 25, 37, 0.18);
        scrollbar-width: thin;
        scrollbar-color: #2c6570 transparent;
      }
      .report-nav__label {
        flex: 0 0 auto;
        margin-right: 14px;
        color: #42d7d0;
        font-size: 8pt;
        font-weight: bold;
        letter-spacing: 1px;
        text-transform: uppercase;
      }
      .report-nav a {
        flex: 0 0 auto;
        padding: 8px 10px;
        color: #aebfc5;
        border: 1px solid transparent;
        font-family: "Liberation Mono", monospace;
        font-size: 8pt;
        text-decoration: none;
        transition: color 150ms ease, border-color 150ms ease, background 150ms ease;
      }
      .report-nav a:hover,
      .report-nav a:focus {
        color: #edfffd;
        border-color: #28736f;
        background: #10323d;
        outline: none;
      }
      .vulnerability {
        scroll-margin-top: 74px;
      }
    }
    @media screen and (max-width: 720px) {
      body > section:not(.cover) {
        padding: 30px 20px 40px;
      }
      .cover {
        min-height: 100vh !important;
        padding: 54px 24px 36px !important;
      }
      .report-nav {
        min-height: 52px;
        padding: 7px 12px;
      }
      .report-nav__label {
        margin-right: 7px;
      }
    }
    h1, h2, h3, h4 { color: #102f3b; page-break-after: avoid; }
    h1 { margin: 0; font-size: 31pt; line-height: 1.05; letter-spacing: -1px; }
    h2 { margin: 6mm 0 4mm; padding-bottom: 2.5mm; border-bottom: 2px solid #159c98; font-size: 20pt; }
    h3 { margin: 5mm 0 2mm; font-size: 12.5pt; }
    p { margin: 0 0 3mm; }
    ul { margin: 1mm 0 4mm; padding-left: 6mm; }
    li { margin-bottom: 1.2mm; }
    code, pre { font-family: "Liberation Mono", "Courier New", monospace; }
    code { color: #087b75; }
    pre {
      margin: 2mm 0 5mm;
      padding: 4mm;
      color: #d8f6ed;
      background: #0a1c26;
      border-left: 4px solid #28c7be;
      font-size: 8.2pt;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      page-break-inside: avoid;
    }
    table { width: 100%; border-collapse: collapse; page-break-inside: avoid; }
    th, td { padding: 2.2mm 2.5mm; border: 1px solid #c9d6da; vertical-align: top; }
    th { color: #31515d; background: #e9f0f1; font-size: 8.5pt; text-align: left; }
    .cover {
      min-height: 245mm;
      padding: 20mm 16mm 14mm;
      color: #edf8f7;
      background: #071925;
      page-break-after: always;
    }
    .cover .classification {
      display: inline-block;
      margin-bottom: 32mm;
      padding: 2mm 3mm;
      color: #46ddd4;
      border: 1px solid #25736f;
      font-size: 8pt;
      letter-spacing: 1.5px;
    }
    .cover h1 { color: #f0f7f8; }
    .cover h1 span { display: block; color: #42d7d0; }
    .cover .subtitle {
      max-width: 125mm;
      margin-top: 8mm;
      color: #9fb6bf;
      font-size: 13pt;
      line-height: 1.6;
    }
    .cover .cover-line { width: 28mm; height: 1px; margin: 13mm 0; background: #42d7d0; }
    .cover .meta {
      margin-top: 45mm;
      color: #acc0c8;
      border-top: 1px solid #25404b;
    }
    .cover .meta td { padding: 4mm 0; border: 0; border-bottom: 1px solid #25404b; background: transparent; }
    .cover .meta td:first-child { width: 42mm; color: #5f8795; font-size: 8pt; text-transform: uppercase; }
    .section-tag {
      margin-top: 2mm;
      color: #0b8e89;
      font-size: 7.5pt;
      font-weight: bold;
      letter-spacing: 1.2px;
    }
    .page-break { page-break-before: always; }
    .intro-box, .notice {
      margin: 4mm 0;
      padding: 4mm;
      border-left: 4px solid #159c98;
      background: #edf7f6;
    }
    .notice.warning { border-color: #d19b2b; background: #fff8e9; }
    .notice.muted { border-color: #81939a; background: #f2f4f5; }
    .mapping-table td:first-child { width: 35%; font-family: "Liberation Mono", monospace; font-weight: bold; }
    .path-card {
      margin: 3mm 0;
      padding: 4mm;
      border: 1px solid #cbd8dc;
      border-left: 5px solid #159c98;
      background: #f7faf9;
      page-break-inside: avoid;
    }
    .path-card strong { color: #0b7874; }
    .graph-image {
      display: block;
      width: 165mm;
      max-height: 128mm;
      margin: 5mm auto;
      object-fit: contain;
      border: 1px solid #b9c8cc;
    }
    .summary-table { font-size: 8.2pt; }
    .summary-table th { color: white; background: #163e4b; }
    .summary-table td:nth-child(1), .summary-table td:nth-child(4) { white-space: nowrap; }
    .risk-high { color: #a91f36; font-weight: bold; }
    .risk-medium { color: #9a6811; font-weight: bold; }
    .risk-low { color: #27764c; font-weight: bold; }
    .risk-na, .risk-none { color: #6e7c82; font-weight: bold; }
    .identity-table { margin: 3mm 0 5mm; font-size: 8.4pt; }
    .identity-table th { width: 18%; }
    .identity-table td { width: 32%; }
    .cvss-block {
      margin-top: 7mm;
      padding: 5mm;
      border: 1px solid #aebfc5;
      background: #f4f8f8;
      page-break-inside: auto;
    }
    .cvss-heading { display: table; width: 100%; }
    .cvss-heading > div { display: table-cell; vertical-align: middle; }
    .cvss-heading span { color: #168d88; font-size: 7pt; font-weight: bold; letter-spacing: 1px; }
    .cvss-heading h3 { margin: 1mm 0 0; }
    .score {
      width: 28mm;
      padding: 3mm;
      color: white !important;
      background: #be3448;
      text-align: center;
    }
    .score.risk-medium { background: #c18b27; }
    .score.risk-low { background: #37835a; }
    .score.risk-na, .score.risk-none { background: #718087; }
    .score strong { display: block; color: white; font-size: 24pt; line-height: 1; }
    .score small { display: block; margin-top: 1mm; color: white; font-size: 7pt; text-transform: uppercase; }
    .vector {
      margin: 4mm 0 2mm;
      padding: 2.5mm;
      background: #e3eeee;
      font-size: 9pt;
    }
    .rationale { color: #506871; font-size: 9pt; }
    .matrix-layout { width: 100%; }
    .matrix-layout > div { margin: 3mm 0; }
    .risk-matrix { width: 100%; table-layout: fixed; font-size: 7.5pt; text-align: center; }
    .risk-matrix caption { margin-bottom: 2mm; color: #36545f; font-weight: bold; text-align: left; }
    .risk-matrix th, .risk-matrix td { height: 9mm; padding: 1mm; text-align: center; }
    .risk-matrix th { background: #dce7e9; }
    .matrix-low { background: #dff0e6; }
    .matrix-medium { background: #f6e9bf; }
    .matrix-high { background: #f3ced3; }
    .matrix-point {
      display: inline-block;
      min-width: 7mm;
      padding: 1.2mm;
      color: white;
      background: #0a6f6b;
      border-radius: 50%;
      font-weight: bold;
    }
    .matrix-unavailable {
      padding: 7mm;
      color: #62747b;
      border: 1px dashed #9daeb4;
      background: #edf1f2;
      text-align: center;
    }
    .metrics-table { margin-top: 3mm; font-size: 8pt; }
    .metrics-table th { color: white; background: #2b5563; }
    .calculation { margin-top: 4mm; padding: 3mm 4mm; background: #0d2732; page-break-inside: avoid; }
    .calculation p { position: relative; margin: 0; padding: 2.5mm 18mm 2.5mm 0; color: #c7d9df; border-bottom: 1px solid #29444f; }
    .calculation p:last-child { border-bottom: 0; }
    .calculation strong { color: white; }
    .calculation code { color: #72ddd3; font-size: 8pt; }
    .calculation span { float: right; color: #72ddd3; font-weight: bold; }
    .method-list { counter-reset: method; padding: 0; list-style: none; }
    .method-list li { margin: 3mm 0; padding: 3mm 3mm 3mm 13mm; border-left: 3px solid #159c98; background: #f2f7f7; }
    .method-list li:before { counter-increment: method; content: counter(method); margin-left: -9mm; margin-right: 4mm; color: #159c98; font-weight: bold; }
    .footer-note { margin-top: 10mm; color: #73868d; font-size: 8pt; text-align: center; }
  </style>
</head>
<body>
  <section class="cover">
    <div class="classification">LIVRABLE D’AUDIT · LABORATOIRE PÉDAGOGIQUE</div>
    <h1>Rapport d’audit<span>EvilCorp</span></h1>
    <p class="subtitle">Analyse des chemins d’exploitation, preuves techniques, impacts, recommandations et matrices de risque CVSS v2.</p>
    <div class="cover-line"></div>
    <table class="meta">
      <tr><td>Cible</td><td>10.10.10.83</td></tr>
      <tr><td>Périmètre</td><td>Applications web, FTP, SSH et élévations locales</td></tr>
      <tr><td>Date</td><td>3 juillet 2026</td></tr>
      <tr><td>Version</td><td>1.0</td></tr>
      <tr><td>Classification</td><td>Usage pédagogique — diffusion contrôlée</td></tr>
    </table>
  </section>

  <section>
    <div class="section-tag">01 · SYNTHÈSE</div>
    <h2>Synthèse exécutive</h2>
    <p>L’audit du laboratoire EvilCorp a permis d’identifier plusieurs points d’entrée distants et trois chaînes d’exploitation confirmées menant à une compromission complète du compte Root.</p>
    <div class="intro-box">
      <strong>Résultat principal.</strong> Sept vulnérabilités sont confirmées. VULN-02 possède une méthode de validation probable par attaque Hydra, mais reste provisoire. VULN-09 n’est pas identifiée et ne reçoit donc aucun score CVSS.
    </div>
    <h3>Chemins confirmés vers Root</h3>
    <div class="path-card"><strong>Chemin 1 — Application PINGOZAURUS</strong><br>Kali → VULN-01 → www-data → VULN-05 → John → VULN-06 → Root</div>
    <div class="path-card"><strong>Chemin 2 — FTP / Alice</strong><br>Kali → VULN-03 → Alice → VULN-07 → Root</div>
    <div class="path-card"><strong>Chemin 3 — EvilCorp Web / Bob</strong><br>Kali → VULN-04 → Bob → VULN-08 → Root</div>
    <h3>Chemins à confirmer</h3>
    <div class="path-card"><strong>VULN-02</strong><br>Kali → attaque par dictionnaire SSH à valider → John</div>
    <div class="path-card"><strong>VULN-09</strong><br>Kali → mécanisme non identifié → Root</div>
  </section>

  <section class="page-break">
    <div class="section-tag">02 · CARTOGRAPHIE</div>
    <h2>Cartographie des chemins d’attaque</h2>
    <img class="graph-image" src="${graphDataUri}" alt="Schéma des chemins d’exploitation EvilCorp">
    <h3>Correspondance des nœuds</h3>
    <table class="mapping-table">
      <tr><td>You</td><td>Machine d’attaque / Kali</td></tr>
      <tr><td>User W</td><td>www-data</td></tr>
      <tr><td>User J</td><td>John</td></tr>
      <tr><td>User A</td><td>Alice</td></tr>
      <tr><td>User B</td><td>Bob</td></tr>
      <tr><td>User R</td><td>Root</td></tr>
    </table>
  </section>

  <section class="page-break">
    <div class="section-tag">03 · MÉTHODOLOGIE</div>
    <h2>Méthodologie et scoring</h2>
    <ol class="method-list">
      <li>Reconnaissance des services exposés et identification des surfaces d’attaque.</li>
      <li>Validation manuelle des vulnérabilités et conservation des commandes reproductibles.</li>
      <li>Énumération post-exploitation depuis chaque identité compromise.</li>
      <li>Construction des chaînes menant aux privilèges Root.</li>
      <li>Évaluation CVSS v2 de chaque vulnérabilité isolée.</li>
    </ol>
    <h3>Convention CVSS v2</h3>
    <p>Le score présenté est le score de base CVSS v2. Il mesure les propriétés intrinsèques de chaque vulnérabilité et non la gravité cumulée de toute la chaîne. Les vecteurs d’accès sont fixés à <code>AV:N</code> conformément au contexte du TP, dans lequel la cible <code>10.10.10.83</code> est considérée comme distante.</p>
    <table>
      <tr><th>Plage</th><th>Niveau</th><th>Interprétation</th></tr>
      <tr><td>0,0</td><td>Nul</td><td>Aucun impact calculé</td></tr>
      <tr><td>0,1 à 3,9</td><td class="risk-low">Faible</td><td>Risque intrinsèque limité</td></tr>
      <tr><td>4,0 à 6,9</td><td class="risk-medium">Modéré</td><td>Risque significatif</td></tr>
      <tr><td>7,0 à 10,0</td><td class="risk-high">Élevé</td><td>Risque majeur nécessitant une correction prioritaire</td></tr>
    </table>
    <p class="footer-note">Référence : FIRST — Common Vulnerability Scoring System v2.0, https://www.first.org/cvss/v2/guide</p>
  </section>

  <section class="page-break">
    <div class="section-tag">04 · SYNTHÈSE DES RISQUES</div>
    <h2>Tableau de synthèse</h2>
    <table class="summary-table">
      <thead><tr><th>ID</th><th>Vulnérabilité</th><th>Chemin</th><th>CVSS</th><th>Risque</th><th>Statut</th></tr></thead>
      <tbody>${summaryRows}</tbody>
    </table>
    <div class="notice warning">
      <strong>Priorisation.</strong> Les élévations VULN-06, VULN-07 et VULN-08 obtiennent les scores les plus élevés dans le contexte imposé du TP. Les points d’entrée distants doivent néanmoins être corrigés conjointement pour casser les chaînes complètes.
    </div>
  </section>

  ${vulnerabilities.map(vulnerabilitySection).join("")}

  <section class="page-break">
    <div class="section-tag">05 · PLAN DE REMÉDIATION</div>
    <h2>Plan de remédiation priorisé</h2>
    <table>
      <thead><tr><th>Priorité</th><th>Actions</th><th>Vulnérabilités concernées</th></tr></thead>
      <tbody>
        <tr><td><strong>P1 — Immédiate</strong></td><td>Supprimer les chemins d’élévation Root : corriger le cron tar, retirer la règle sudo tee et supprimer le bit SUID de find.</td><td>VULN-06, VULN-07, VULN-08</td></tr>
        <tr><td><strong>P1 — Immédiate</strong></td><td>Corriger les injections de commandes et SQL avec des API sûres et des requêtes préparées.</td><td>VULN-01, VULN-04</td></tr>
        <tr><td><strong>P1 — Immédiate</strong></td><td>Révoquer les secrets exposés, renouveler les clés et mots de passe, supprimer les données sensibles des scripts et interfaces.</td><td>VULN-03, VULN-04, VULN-05</td></tr>
        <tr><td><strong>P2 — Rapide</strong></td><td>Désactiver FTP anonyme et l’authentification SSH par mot de passe lorsque possible ; déployer une limitation des tentatives.</td><td>VULN-02, VULN-03</td></tr>
        <tr><td><strong>P3 — Investigation</strong></td><td>Reproduire l’attaque Hydra de VULN-02 et poursuivre l’identification de VULN-09 sans leur attribuer de conclusion prématurée.</td><td>VULN-02, VULN-09</td></tr>
      </tbody>
    </table>
    <h3>Conclusion</h3>
    <p>La compromission complète du laboratoire repose sur l’enchaînement de faiblesses applicatives, de secrets exposés et de configurations privilégiées dangereuses. La correction d’une seule étape réduit le risque, mais la remédiation doit viser l’ensemble des maillons afin d’empêcher les chemins alternatifs.</p>
    <div class="footer-note">Fin du rapport — EvilCorp · 3 juillet 2026</div>
  </section>
</body>
</html>`;

await mkdir(outputDirectory, { recursive: true });
await mkdir(publicDirectory, { recursive: true });
await writeFile(outputFile, html, "utf8");
const reportNavigation = `
  <nav class="report-nav" aria-label="Navigation des vulnérabilités">
    <span class="report-nav__label">Accès rapide</span>
    ${vulnerabilities
      .map(
        (vulnerability) =>
          `<a href="#${vulnerability.id}" title="${escapeHtml(vulnerability.title)}">${escapeHtml(vulnerability.label.toUpperCase())}</a>`,
      )
      .join("")}
  </nav>`;
const publicHtml = html.replace("<body>", `<body>${reportNavigation}`);
await writeFile(publicFile, publicHtml, "utf8");
console.log(`${outputFile}\n${publicFile}`);
