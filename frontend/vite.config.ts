import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      port: 3000,
      proxy: {
        '/api': {
          target: env.VITE_API_URL || 'http://localhost:8080',
          changeOrigin: true,
          secure: false,
        },
        '/ws': {
          target: env.VITE_WS_URL || 'http://localhost:8080',
          changeOrigin: true,
          ws: true,
          secure: false,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: mode !== 'production',
      rollupOptions: {
        output: {
          // Heavy libs are split out so a page that does not use them never
          // pays their download/parse cost on mobile. Splitting also lets the
          // browser cache each lib independently across deploys.
          manualChunks: {
            vendor: ['react', 'react-dom', 'react-router-dom'],
            query: ['@tanstack/react-query'],
            ui: ['@radix-ui/react-dialog', '@radix-ui/react-select'],
            charts: ['recharts'],
            terminal: ['xterm', '@xterm/addon-fit'],
            dates: ['date-fns'],
            icons: ['lucide-react'],
          },
        },
      },
    },
    define: {
      __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    },
  }
})
