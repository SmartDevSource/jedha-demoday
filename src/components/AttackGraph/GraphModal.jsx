import {
  Activity,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  CircleUserRound,
  Server,
  ShieldAlert,
  TerminalSquare,
  X,
} from "lucide-react";
import React, { useEffect, useRef, useState } from "react";
import { CvssMatrix } from "./CvssMatrix";

function VulnerabilityDetails({ item }) {
  const isUnconfirmed = item.status === "Non confirmée";
  const [showCvss, setShowCvss] = useState(false);

  useEffect(() => {
    setShowCvss(false);
  }, [item.id]);

  return (
    <div className="vulnerability-details">
      <div className="vulnerability-summary">
        <span className={`severity-badge ${isUnconfirmed ? "is-unconfirmed" : ""}`}>
          <ShieldAlert size={14} aria-hidden="true" />
          {item.severity}
        </span>
        <span className={`verification-status ${isUnconfirmed ? "is-unconfirmed" : ""}`}>
          {isUnconfirmed ? <Activity size={13} /> : <CheckCircle2 size={13} />}
          {item.status}
        </span>
      </div>

      <p className="vulnerability-description">{item.description}</p>

      <dl className="vulnerability-metadata">
        <div>
          <dt><Server size={15} /> Service concerné</dt>
          <dd>{item.service}</dd>
        </div>
        <div>
          <dt><CircleUserRound size={15} /> Utilisateur obtenu</dt>
          <dd>{item.obtainedUser}</dd>
        </div>
      </dl>

      <div className="cvss-disclosure">
        <button
          className="cvss-trigger"
          type="button"
          aria-expanded={showCvss}
          onClick={() => setShowCvss((current) => !current)}
        >
          <span className="cvss-trigger__icon">
            <BarChart3 size={19} aria-hidden="true" />
          </span>
          <span>
            <strong>Matrice de risque CVSS v2</strong>
            <small>Score, vecteur et calculs détaillés</small>
          </span>
          <ChevronDown
            className="cvss-trigger__chevron"
            size={18}
            aria-hidden="true"
          />
        </button>
        <div className={`cvss-reveal ${showCvss ? "is-open" : ""}`}>
          <div className="cvss-reveal__inner">
            <CvssMatrix cvss={item.cvss} />
          </div>
        </div>
      </div>

      <section className="detail-section">
        <h3><TerminalSquare size={16} /> Preuve d’exploitation</h3>
        <pre><code>{item.proof}</code></pre>
      </section>

      <section className="detail-section">
        <h3>Impact</h3>
        <p>{item.impact}</p>
      </section>

      <section className="detail-section recommendations">
        <h3>Recommandations</h3>
        <ul>
          {item.recommendations.map((recommendation) => (
            <li key={recommendation}>{recommendation}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export function GraphModal({ item, onClose }) {
  const closeButtonRef = useRef(null);
  const modalRef = useRef(null);

  useEffect(() => {
    if (!item) return undefined;

    const previousFocus = document.activeElement;
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
      if (event.key === "Tab") {
        const focusable = modalRef.current?.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
        if (!focusable?.length) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (!modalRef.current.contains(document.activeElement)) {
          event.preventDefault();
          first.focus();
        } else if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", onKeyDown);
    document.body.classList.add("modal-open");
    closeButtonRef.current?.focus();

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.classList.remove("modal-open");
      previousFocus?.focus?.();
    };
  }, [item, onClose]);

  if (!item) return null;

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section
        ref={modalRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="modal-accent" />
        <header className="modal-header">
          <div>
            <span className="modal-kicker">
              {item.type === "user" ? "Identity node" : `${item.label} · Attack vector`}
            </span>
            <h2 id="modal-title">
              {item.type === "vulnerability" ? item.title : item.label}
            </h2>
          </div>
          <button
            ref={closeButtonRef}
            className="modal-close"
            type="button"
            onClick={onClose}
            aria-label="Fermer la fenêtre"
          >
            <X size={20} />
          </button>
        </header>
        <div className="modal-content">
          {item.type === "vulnerability" && <VulnerabilityDetails item={item} />}
        </div>
      </section>
    </div>
  );
}
