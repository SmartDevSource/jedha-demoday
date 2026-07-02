import React from "react";
import { ShieldCheck } from "lucide-react";
import { AttackGraph } from "./components/AttackGraph/AttackGraph";

export default function App() {
  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="EvilCorp Attack Paths — Accueil">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck size={20} strokeWidth={2.2} />
          </span>
          <span>
            <strong>EvilCorp</strong>
            <small>Attack Paths</small>
          </span>
        </a>

        <span className="status">
          <i aria-hidden="true" />
          Lab environment
        </span>
      </header>

      <main id="top">
        <section className="hero" aria-labelledby="page-title">
          <div className="eyebrow">
            <span>Cybersecurity Project</span>
            <span className="eyebrow-line" />
            <span>01</span>
          </div>
          <div className="hero-copy">
            <h1 id="page-title">
              Cartographie des
              <span> chemins d’attaque</span>
            </h1>
            <p>
              Explorez les vulnérabilités et les relations entre chaque identité
              du système EvilCorp.
            </p>
          </div>
        </section>

        <AttackGraph />
      </main>

      <footer>
        <span>Security assessment</span>
        <span>Interactive topology · 2026</span>
      </footer>
    </div>
  );
}
