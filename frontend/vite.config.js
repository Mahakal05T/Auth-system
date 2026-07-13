import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/login': 'http://127.0.0.1:5000',
      '/register': 'http://127.0.0.1:5000',
      '/logout': 'http://127.0.0.1:5000',
      '/token': 'http://127.0.0.1:5000',
      '/dashboard': 'http://127.0.0.1:5000',
      '/admin': 'http://127.0.0.1:5000',
      '/forgot_password': 'http://127.0.0.1:5000',
      '/reset_password': 'http://127.0.0.1:5000',
      '/unauthorized': 'http://127.0.0.1:5000',
    }
  }
})
