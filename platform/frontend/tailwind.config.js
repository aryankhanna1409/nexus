/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        noc: { bg: "#0b1118", panel: "#111a24", line: "#1f2d3b", text: "#dbe4ee", muted: "#8aa0b5" },
        sev: { critical: "#ff5d5d", high: "#ff9f43", medium: "#f7d046", low: "#5dade2", ok: "#2ecc71" },
      },
    },
  },
  plugins: [],
};
