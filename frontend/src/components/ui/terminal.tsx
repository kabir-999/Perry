import { useEffect, useRef, useState } from "react";
import { cn } from "../../lib/utils";

type TerminalLine = { type: "command" | "output"; text: string };

type TerminalProps = {
  commands: string[];
  outputs?: Record<number, string[]>;
  typingSpeed?: number;
  delayBetweenCommands?: number;
  className?: string;
};

export function Terminal({
  commands,
  outputs = {},
  typingSpeed = 45,
  delayBetweenCommands = 1000,
  className,
}: TerminalProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [typed, setTyped] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    async function run() {
      let index = 0;
      while (!cancelled) {
        const command = commands[index];
        let current = "";
        for (const char of command) {
          if (cancelled) return;
          current += char;
          setTyped(current);
          await sleep(typingSpeed);
        }
        if (cancelled) return;
        setLines((prev) => [...prev, { type: "command", text: command }]);
        setTyped("");

        for (const line of outputs[index] ?? []) {
          if (cancelled) return;
          await sleep(120);
          setLines((prev) => [...prev, { type: "output", text: line }]);
        }

        await sleep(delayBetweenCommands);
        index = (index + 1) % commands.length;
        if (index === 0) setLines([]);
      }
    }

    run();
    return () => {
      cancelled = true;
    };
  }, [commands, outputs, typingSpeed, delayBetweenCommands]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [lines, typed]);

  return (
    <div className={cn("overflow-hidden rounded-xl border border-[#2a2f36] bg-[#0d1117] shadow-lg", className)}>
      <div className="flex items-center gap-1.5 border-b border-[#2a2f36] bg-[#161b22] px-4 py-2.5">
        <span className="h-3 w-3 rounded-full bg-[#ff5f56]" />
        <span className="h-3 w-3 rounded-full bg-[#ffbd2e]" />
        <span className="h-3 w-3 rounded-full bg-[#27c93f]" />
      </div>
      <div ref={scrollRef} className="h-64 overflow-y-auto p-4 font-mono text-sm leading-relaxed">
        {lines.map((line, i) => (
          <div key={i} className={line.type === "command" ? "text-[#e6edf3]" : "text-[#7ee787]"}>
            {line.type === "command" && <span className="text-[#58a6ff]">$ </span>}
            {line.text}
          </div>
        ))}
        <div className="text-[#e6edf3]">
          <span className="text-[#58a6ff]">$ </span>
          {typed}
          <span className="animate-pulse">▌</span>
        </div>
      </div>
    </div>
  );
}

export default Terminal;
