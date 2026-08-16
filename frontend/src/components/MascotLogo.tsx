import perryLogo from "../Perry-Logo_bgremoved.png";

type MascotLogoProps = {
  size?: "sm" | "md" | "lg";
  showWordmark?: boolean;
  className?: string;
};

const SIZE_CLASS = {
  sm: "h-10 w-24",
  // Used for every page's top-left header logo (Login, Home, the
  // authenticated Layout nav) — bumped up since it was reading too small
  // there. Scales down a step on phones so it doesn't crowd a narrow header.
  md: "h-14 w-36 sm:h-20 sm:w-52",
  lg: "h-28 w-72 sm:h-36 sm:w-96",
};

export default function MascotLogo({
  size = "md",
  showWordmark = false,
  className = "",
}: MascotLogoProps) {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <span
        className={`${SIZE_CLASS[size]} grid shrink-0 place-items-center overflow-hidden bg-transparent`}
        aria-hidden="true"
      >
        <img
          src={perryLogo}
          alt=""
          className="h-full w-full object-contain"
        />
      </span>
      {showWordmark && (
        <div className="leading-tight">
          <p className="text-sm font-semibold tracking-tight text-[#123331]">
            Perry
          </p>
          <p className="text-[11px] text-[#66837d]">Web Security Scanner</p>
        </div>
      )}
    </div>
  );
}
