import { useMemo } from "react";
import perryImg from "../Perry.png";
import { PERRY_DOTS, PERRY_H, PERRY_W } from "../perryDots";

/**
 * Perry's face, built from real pixel data sampled from Perry.png (see
 * perryDots.ts) rather than a hand-approximated vector — a hand-drawn trace
 * kept coming out looking cheap/wrong next to the real artwork, so the dots
 * assemble from the actual image's own colors and shape, then the real PNG
 * itself fades in on top as the crisp, guaranteed-correct final frame.
 */

type Dot = { x: number; y: number; c: string; delay: number };

function withDelay(): Dot[] {
  return PERRY_DOTS.map((d) => ({
    ...d,
    delay: (d.y / PERRY_H) * 650 + Math.random() * 220,
  }));
}

export default function PerryFaceReveal({ className = "" }: { className?: string }) {
  const dots = useMemo(withDelay, []);
  const resolveDelay = 950;

  return (
    <svg
      viewBox={`0 0 ${PERRY_W} ${PERRY_H}`}
      className={className}
      aria-hidden="true"
      style={{ overflow: "visible" }}
    >
      {/* Dot-matrix assembly, sampled straight from the source image */}
      <g>
        {dots.map((d, i) => (
          <circle
            key={i}
            cx={d.x}
            cy={d.y}
            r={1.7}
            fill={d.c}
            className="dot-pop"
            style={{ transformOrigin: `${d.x}px ${d.y}px`, animationDelay: `${d.delay}ms` }}
          />
        ))}
      </g>

      {/* The real artwork, resolves in on top once the dots finish */}
      <image
        href={perryImg}
        x={0}
        y={0}
        width={PERRY_W}
        height={PERRY_H}
        className="face-resolve"
        style={{ animationDelay: `${resolveDelay}ms` }}
      />
    </svg>
  );
}
