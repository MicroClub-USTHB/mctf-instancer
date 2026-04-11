/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./admin.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["Chakra Petch", "sans-serif"],
        body: ["Public Sans", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },
      colors: {
        graphite: "#0D0D0D",
        anthracite: "#262626",
        steel: "#737373",
        mist: "#F2F2F2",
        deepviolet: "#200F38",
      },
      boxShadow: {
        spotlight: "0 35px 90px rgba(6, 6, 6, 0.75)",
      },
    },
  },
  plugins: [],
};
