import { heroui } from "@heroui/theme";

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/layouts/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  darkMode: "class",
  plugins: [
    heroui({
      themes: {
          dark: {
              extend: "dark",
              colors: {
                  danger: {
                      50: "#6c0909",
                      100: "#830f0f",
                      200: "#a21818",
                      300: "#c22323",
                      400: "#e23131",
                      500: "#ed6262",
                      600: "#f68282",
                      700: "#fcadad",
                      800: "#fdd5d5",
                      900: "#feecec",
                      DEFAULT: "#ed6262",
                      foreground: "#ffffff",
                  },
                  foreground: "#ffffff",
                  primary: {
                      50: "#6c0909",
                      100: "#830f0f",
                      200: "#a21818",
                      300: "#c22323",
                      400: "#e23131",
                      500: "#ed6262",
                      600: "#f68282",
                      700: "#fcadad",
                      800: "#fdd5d5",
                      900: "#feecec",
                      DEFAULT: "#ed6262",
                      foreground: "#ffffff",
                  },
                  focus: "#f68282",
              },
          },
          light: {
              extend: "dark",
              colors: {
                  danger: {
                      50: "#6c0909",
                      100: "#830f0f",
                      200: "#a21818",
                      300: "#c22323",
                      400: "#e23131",
                      500: "#ed6262",
                      600: "#f68282",
                      700: "#fcadad",
                      800: "#fdd5d5",
                      900: "#feecec",
                      DEFAULT: "#ed6262",
                      foreground: "#131313FF",
                  },
                  foreground: "#131313",
                  primary: {
                      50: "#6c0909",
                      100: "#830f0f",
                      200: "#a21818",
                      300: "#c22323",
                      400: "#e23131",
                      500: "#ed6262",
                      600: "#f68282",
                      700: "#fcadad",
                      800: "#fdd5d5",
                      900: "#feecec",
                      DEFAULT: "#ed6262",
                      foreground: "#131313FF",
                  },
                  focus: "#f68282",
              },
          },
      },
    }),
  ],
};
