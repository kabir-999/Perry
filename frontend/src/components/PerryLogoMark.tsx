/**
 * Vector recreation of the Perry wordmark — a tilted fedora above bold
 * "PERRY" letterforms — traced (via potrace) directly from the pixels of
 * Perry-Logo_bgremoved.png, so it renders crisp at any size instead of
 * scaling a raster PNG. Colors sampled from that same source image: hat
 * #41220E, wordmark #2E3939. A standalone copy of the same mark lives at
 * public/perry-logo.svg.
 */
export default function PerryLogoMark({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 640 220"
      className={className}
      role="img"
      aria-label="Perry"
    >
      <g transform="translate(30,15) scale(2.0)">
        <g
          transform="translate(-73.500000,54.274976) scale(0.100000,-0.100000)"
          fill="#41220E"
          stroke="none"
        >
          <path
            d="M979 494 c-24 -58 -39 -137 -39 -216 l0 -56 -32 -20 c-18 -11 -59
              -36 -90 -55 -32 -19 -63 -37 -70 -40 l-13 -5 30 -12 c17 -7 51 -15 76 -17 l45
              -5 78 21 c72 20 134 48 266 122 l55 30 65 15 64 15 26 -31 25 -31 46 32 c25
              18 56 47 67 64 l22 31 0 27 0 27 -26 17 -26 17 -47 -13 c-25 -8 -55 -16 -67
              -18 l-21 -5 -35 64 -35 63 -22 11 -23 12 -27 -8 c-14 -5 -40 -14 -57 -21 l-32
              -12 -36 17 -37 18 -54 5 -55 6 -21 -49z m187 -32 c38 -17 71 -29 73 -27 2 3
              -1 11 -7 18 l-12 14 26 11 c14 7 34 12 44 12 l20 0 30 -52 c16 -29 26 -54 22
              -55 -4 -1 -56 -7 -117 -12 l-110 -10 -74 -26 c-41 -14 -76 -25 -79 -25 -9 0
              10 106 34 179 l4 14 38 -6 c21 -2 70 -18 108 -35z m48 -211 c-76 -54 -124 -81
              -191 -106 l-67 -26 -61 -5 -60 -6 70 47 c39 26 90 56 115 67 53 23 175 57 209
              57 l24 1 -39 -29z"
          />
        </g>
      </g>

      <text
        x="345"
        y="196"
        textAnchor="middle"
        fontFamily="'Helvetica Neue', Arial, sans-serif"
        fontWeight="800"
        fontSize="108"
        letterSpacing="2"
        fill="#2E3939"
      >
        PERRY
      </text>
    </svg>
  );
}
