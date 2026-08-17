import { useEffect, useState } from "react";

/**
 * Types out each line of a headline character by character, terminal-style,
 * with a blinking caret at the current write position.
 */
export default function TypewriterHeadline({
  lines,
  start,
  speed = 32,
  lineDelay = 260,
  className = "",
}: {
  lines: string[];
  start: boolean;
  speed?: number;
  lineDelay?: number;
  className?: string;
}) {
  const [lineIdx, setLineIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);

  useEffect(() => {
    if (!start || lineIdx >= lines.length) return;
    const line = lines[lineIdx];
    if (charIdx < line.length) {
      const t = setTimeout(() => setCharIdx((c) => c + 1), speed);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      setLineIdx((l) => l + 1);
      setCharIdx(0);
    }, lineDelay);
    return () => clearTimeout(t);
  }, [start, lineIdx, charIdx, lines, speed, lineDelay]);

  const finished = lineIdx >= lines.length;

  return (
    <span className={className}>
      {lines.map((line, i) => {
        const text = i < lineIdx ? line : i === lineIdx ? line.slice(0, charIdx) : "";
        return (
          <span key={line} className="block min-h-[1em]">
            {text}
            {!finished && i === lineIdx && (
              <span className="typing-cursor" aria-hidden="true" />
            )}
          </span>
        );
      })}
    </span>
  );
}
