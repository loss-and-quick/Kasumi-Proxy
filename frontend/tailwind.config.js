/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        ui: ["Roboto", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: {
        card: "18px",
        pill: "100px",
      },
      spacing: {
        "row-y": "var(--row-pad-y)",
      },
    },
  },
  plugins: [],
};
