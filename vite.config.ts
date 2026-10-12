/// <reference types="vitest" />
import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, cpSync, existsSync } from 'fs';

// Custom lightweight plugin to copy manifest, locales, and icons to dist
function chromeExtensionPlugin() {
  return {
    name: 'chrome-extension-plugin',
    closeBundle() {
      // Ensure dist directories exist
      if (!existsSync('dist')) mkdirSync('dist', { recursive: true });

      // Copy manifest.json
      copyFileSync('manifest.json', 'dist/manifest.json');

      // Copy _locales
      if (existsSync('_locales')) {
        cpSync('_locales', 'dist/_locales', { recursive: true });
      }

      // Copy icons
      if (existsSync('icons')) {
        cpSync('icons', 'dist/icons', { recursive: true });
      }
    },
  };
}

export default defineConfig({
  test: {
    testTimeout: 30000,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        content: resolve(__dirname, 'src/content/content.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return 'background/service-worker.js';
          }
          if (chunkInfo.name === 'content') {
            return 'content/content.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
  plugins: [chromeExtensionPlugin()],
});
