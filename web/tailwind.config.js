/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      keyframes: {
        'glow-pulse': {
          '0%, 100%': {
            boxShadow: '0 0 5px rgba(22, 163, 74, 0.5), 0 0 10px rgba(22, 163, 74, 0.3)',
            opacity: '1'
          },
          '50%': {
            boxShadow: '0 0 20px rgba(22, 163, 74, 0.8), 0 0 30px rgba(22, 163, 74, 0.5)',
            opacity: '0.8'
          },
        },
        'cursor-blink': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite',
        'cursor-blink': 'cursor-blink 1s step-end infinite',
        'fade-in': 'fade-in 0.3s ease-out',
      },
      fontSize: {
        'logo-xs': ['0.6rem', '1.5'],
        'logo-sm': ['0.875rem', '1.5'],
        'logo-md': ['1rem', '1.5'],
        'logo-lg': ['1.125rem', '1.5'],
      },
    },
  },
  plugins: [],
}
