import { defineConfig, build } from 'vite';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, cpSync, existsSync } from 'fs';

// Custom lightweight plugin to build standalone IIFE content script and copy static assets
function chromeExtensionPlugin() {
  return {
    name: 'chrome-extension-plugin',
    async closeBundle() {
      // Skip during vitest unit tests
      if (process.env.VITEST) return;

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

      // Build standalone IIFE content script.
      // Chrome Manifest V3 content scripts run as classic scripts and do NOT support ES module import syntax.
      await build({
        configFile: false,
        build: {
          outDir: 'dist',
          emptyOutDir: false,
          target: 'es2022',
          rollupOptions: {
            input: resolve(__dirname, 'src/content/content.ts'),
            output: {
              format: 'iife',
              entryFileNames: 'content/content.js',
              inlineDynamicImports: true,
            },
          },
        },
      });
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
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return 'background/service-worker.js';
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

