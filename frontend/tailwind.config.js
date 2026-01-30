/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'], // Forces JetBrains for everything
      },
      colors: {
        cyber: {
          black: '#050505',
          dark: '#0a0f14',
          neon: '#00f3ff',
          alert: '#ff003c',
          dim: 'rgba(0, 243, 255, 0.1)'
        }
      }
    },
  },
  plugins: [],
}