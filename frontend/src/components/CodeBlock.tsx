import { useState } from "react";

export default function CodeBlock({
  label,
  code,
  glow = true,
}: {
  label: string;
  code: string;
  glow?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be denied by the browser; nothing to recover.
    }
  }

  return (
    <div
      className={`overflow-hidden rounded-xl border border-[#1c3d39] bg-[#0f2624] shadow-sm ${
        glow ? "glow-teal" : ""
      }`}
    >
      <div className="flex items-center justify-between border-b border-[#1c3d39] bg-[#0b2321] px-4 py-2">
        <span className="text-xs font-medium text-[#8fbab1]">{label}</span>
        <button
          onClick={handleCopy}
          className="rounded-md px-2 py-1 text-xs font-medium text-[#8fbab1] transition-colors hover:bg-white/5 hover:text-white"
          aria-label="Copy to clipboard"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-3 text-sm leading-relaxed">
        <code className="font-mono text-[#dff0ec]">{code}</code>
      </pre>
    </div>
  );
}
