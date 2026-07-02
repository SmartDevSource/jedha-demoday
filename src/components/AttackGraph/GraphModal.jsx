import { X } from "lucide-react";
import React, { useEffect, useRef } from "react";

export function GraphModal({ item, onClose }) {
  const closeButtonRef = useRef(null);

  useEffect(() => {
    if (!item) return undefined;

    const previousFocus = document.activeElement;
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
      if (event.key === "Tab") {
        event.preventDefault();
        closeButtonRef.current?.focus();
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
              {item.type === "user" ? "Identity node" : "Attack vector"}
            </span>
            <h2 id="modal-title">{item.label}</h2>
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
        <div className="modal-content" aria-label="Contenu à venir" />
      </section>
    </div>
  );
}
