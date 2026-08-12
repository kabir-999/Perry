/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: "#e11d48",
          high: "#ea580c",
          medium: "#d97706",
          low: "#0d9488",
          minimal: "#16a34a",
          info: "#78716c",
        },
      },
    },
  },
  plugins: [],
};
