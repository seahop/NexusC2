/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./layouts/**/*.html",
    "./content/**/*.md",
    "./content/**/*.html",
  ],
  theme: {
    extend: {
      colors: {
        nexus: {
          green: {
            500: '#00ff00',
            400: '#4ade80',
            300: '#86efac',
            600: '#00cc00',
            700: '#009900',
          },
          black: {
            500: '#000000',
            400: '#0d0d0d',
            300: '#1a1a1a',
            200: '#262626',
            100: '#333333',
          },
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'glow': '0 0 20px rgba(0, 255, 0, 0.3)',
        'glow-sm': '0 0 10px rgba(0, 255, 0, 0.2)',
        'glow-lg': '0 0 40px rgba(0, 255, 0, 0.4)',
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'typing': 'typing 3s steps(30) infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(0, 255, 0, 0.3)' },
          '50%': { boxShadow: '0 0 40px rgba(0, 255, 0, 0.5)' },
        },
        'typing': {
          'from': { width: '0' },
          'to': { width: '100%' },
        },
        'blink': {
          '50%': { opacity: '0' },
        },
      },
      typography: {
        DEFAULT: {
          css: {
            color: '#ffffff',
            a: {
              color: '#00ff00',
              '&:hover': {
                color: '#4ade80',
              },
            },
            strong: {
              color: '#ffffff',
            },
            h1: {
              color: '#ffffff',
            },
            h2: {
              color: '#ffffff',
            },
            h3: {
              color: '#ffffff',
            },
            h4: {
              color: '#ffffff',
            },
            code: {
              color: '#00ff00',
              backgroundColor: '#1a1a1a',
              padding: '0.25rem 0.5rem',
              borderRadius: '0.25rem',
              fontWeight: '400',
            },
            'code::before': {
              content: '""',
            },
            'code::after': {
              content: '""',
            },
            pre: {
              backgroundColor: '#0d0d0d',
              border: '1px solid rgba(0, 255, 0, 0.2)',
            },
            blockquote: {
              borderLeftColor: '#00ff00',
              color: '#a3a3a3',
            },
            hr: {
              borderColor: 'rgba(0, 255, 0, 0.2)',
            },
            thead: {
              borderBottomColor: 'rgba(0, 255, 0, 0.3)',
            },
            'thead th': {
              color: '#00ff00',
            },
            'tbody tr': {
              borderBottomColor: 'rgba(0, 255, 0, 0.1)',
            },
            'tbody td': {
              color: '#e5e5e5',
            },
          },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
