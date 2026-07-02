import React, { useCallback, useState } from "react";
import { Maximize2, MousePointer2, Network } from "lucide-react";
import { AttackEdge } from "./AttackEdge";
import { GraphModal } from "./GraphModal";
import { UserNode } from "./UserNode";
import { users, vulnerabilities } from "./graphData";
import "./attackGraph.css";

function CrownNode() {
  return (
    <g className="crown-node" transform="translate(605 139)">
      <circle className="crown-node__ring" r="66" />
      <circle className="crown-node__head" cy="-20" r="28" />
      <path
        className="crown-node__body"
        d="M -49 50 C -46 13 -28 0 -15 -2 C -8 8 0 11 0 11 C 0 11 8 8 15 -2 C 30 0 46 13 49 50 Z"
      />
      <text x="60" y="-13">User R</text>
      <text className="crown-node__role" x="60" y="10">
        Primary target
      </text>
    </g>
  );
}

function Workstation() {
  return (
    <g className="workstation" transform="translate(565 689)">
      <rect x="-44" y="-27" width="88" height="55" rx="5" />
      <path d="M -18 37 L 18 37 M 0 28 L 0 37" />
      <rect x="-34" y="45" width="68" height="14" rx="3" />
      <circle cx="0" cy="0" r="9" />
      <text x="0" y="91" textAnchor="middle">
        You
      </text>
    </g>
  );
}

export function AttackGraph() {
  const [selectedItem, setSelectedItem] = useState(null);
  const closeModal = useCallback(() => setSelectedItem(null), []);

  return (
    <section className="graph-section" aria-labelledby="graph-title">
      <div className="graph-heading">
        <div>
          <span className="section-index">01 / Attack surface</span>
          <h2 id="graph-title">Infrastructure compromise map</h2>
        </div>
        <div className="graph-instruction">
          <MousePointer2 size={16} aria-hidden="true" />
          <span>Cliquez sur un chemin de vulnérabilité</span>
        </div>
      </div>

      <div className="graph-card">
        <div className="graph-toolbar">
          <div className="graph-toolbar__title">
            <span className="graph-toolbar__icon">
              <Network size={17} aria-hidden="true" />
            </span>
            <div>
              <strong>EvilCorp Server</strong>
              <small>Network topology</small>
            </div>
          </div>
          <span className="graph-toolbar__meta">
            <Maximize2 size={14} />
            Interactive canvas
          </span>
        </div>

        <div className="graph-scroll">
          <svg
            className="attack-graph"
            viewBox="0 0 1200 800"
            role="img"
            aria-labelledby="svg-title svg-description"
          >
            <title id="svg-title">Chemins d’attaque du serveur EvilCorp</title>
            <desc id="svg-description">
              Neuf vulnérabilités relient votre poste à quatre utilisateurs et à
              l’utilisateur cible R.
            </desc>

            <rect className="server-zone" x="34" y="34" width="1132" height="535" rx="18" />
            <text className="zone-label" x="66" y="75">
              INTERNAL NETWORK
            </text>
            <circle className="zone-dot" cx="1118" cy="70" r="4" />
            <text className="zone-status" x="1102" y="75" textAnchor="end">
              MONITORED
            </text>

            <g className="edges">
              {vulnerabilities.map((vulnerability) => (
                <AttackEdge
                  key={vulnerability.id}
                  vulnerability={vulnerability}
                  onSelect={setSelectedItem}
                />
              ))}
            </g>

            <CrownNode />
            {users.map((user) => (
              <UserNode key={user.id} user={user} />
            ))}
            <Workstation />
          </svg>
        </div>

        <div className="graph-legend" aria-label="Légende">
          <span><i className="legend-you" /> Point d’entrée</span>
          <span><i className="legend-user" /> Identité compromise</span>
          <span><i className="legend-target" /> Cible principale</span>
        </div>
      </div>

      <GraphModal item={selectedItem} onClose={closeModal} />
    </section>
  );
}
