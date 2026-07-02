import React from "react";

export function AttackEdge({ vulnerability, onSelect }) {
  const markerId = `arrow-${vulnerability.id}`;

  const activate = () =>
    onSelect({ type: "vulnerability", ...vulnerability });

  return (
    <g
      className="attack-edge"
      role="button"
      tabIndex="0"
      aria-label={`Ouvrir ${vulnerability.label}`}
      style={{ "--edge-color": vulnerability.color }}
      onClick={activate}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activate();
        }
      }}
    >
      <defs>
        <marker
          id={markerId}
          markerWidth="8"
          markerHeight="8"
          refX="7"
          refY="4"
          orient="auto"
          markerUnits="strokeWidth"
        >
          <path d="M 0 0 L 8 4 L 0 8 Z" fill={vulnerability.color} />
        </marker>
      </defs>
      <path className="attack-edge__hitbox" d={vulnerability.path} />
      <path
        className="attack-edge__line"
        d={vulnerability.path}
        markerEnd={`url(#${markerId})`}
      />
      <g
        className="attack-edge__label"
        transform={`translate(${vulnerability.labelPosition.x} ${vulnerability.labelPosition.y})`}
      >
        <rect x="-39" y="-14" width="78" height="25" rx="12.5" />
        <text textAnchor="middle" dominantBaseline="middle">
          {vulnerability.label}
        </text>
      </g>
    </g>
  );
}
