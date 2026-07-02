import React from "react";

export function UserNode({ user }) {
  return (
    <g
      className="user-node"
      aria-label={user.name}
      transform={`translate(${user.x} ${user.y})`}
    >
      <circle className="user-node__halo" cy="-22" r="69" />
      <circle className="user-node__head" cy="-41" r="25" />
      <path
        className="user-node__body"
        d="M -47 23 C -44 -7 -27 -19 -14 -20 C -7 -12 0 -9 0 -9 C 0 -9 7 -12 14 -20 C 28 -19 44 -7 47 23 Z"
      />
      <text className="user-node__name" x="0" y="55" textAnchor="middle">
        {user.name}
      </text>
    </g>
  );
}
