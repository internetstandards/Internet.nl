import terser from "@rollup/plugin-terser";
import postcss from "rollup-plugin-postcss";
import { defineConfig } from "rollup";
import fs from "fs";

const isProduction = process.env.NODE_ENV === "production";
const outputDir = process.env.OUTPUT_DIR ?? "dist";

const cleanupOutputDir = () => ({
  name: "cleanup-output-dir",
  buildStart() {
    // Only clean up if not in watch mode
    if (!this.meta.watchMode && fs.existsSync(outputDir)) {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }
  },
});

const defaultPlugins = [
  isProduction &&
    terser({
      compress: {
        drop_console: true,
        drop_debugger: true,
      },
      format: {
        comments: false,
      },
    }),
];

// Define chunks configuration
const chunks = {
  base: [
    "src/js/base/header.js",
    "src/js/base/theme.js",
    "src/js/base/print.js",
    "src/js/lib/matomo.js",
  ],
  results: [
    "src/js/pages/results/copy-link.js",
    "src/js/pages/results/repeat-test-countdown.js",
  ],
  connection: ["src/js/pages/connection/connection.js"],
  probe: ["src/js/pages/probe/probe.js"],
  "components/card-list": ["src/js/components/card-list/load-more.js"],
  "components/carousel": ["src/js/components/carousel/carrousel.js"],
  "components/meter": ["src/js/components/meter/result-meter.js"],
  "components/action-card": [
    "src/js/components/action-card/action-card-fallback.js",
  ],
};

// Create config for each file
const config = [
  // Modern JavaScript bundle (ES modules)
  {
    input: "src/index.js",
    output: {
      format: "es",
      sourcemap: !isProduction,
      dir: `${outputDir}/js`,
      manualChunks: chunks,
      chunkFileNames: "[name]-min.js",
    },
    plugins: [cleanupOutputDir(), ...defaultPlugins],
  },
  // Legacy JavaScript bundle (IIFE)
  {
    input: "src/index.js",
    output: {
      format: "iife",
      sourcemap: !isProduction,
      file: `${outputDir}/js/legacy-min.js`,
    },
    plugins: defaultPlugins,
  },
  // CSS bundle
  {
    input: "src/index.css",
    output: {
      file: `${outputDir}/css/style-min.css`,
    },
    plugins: [
      postcss({
        extract: true,
        minimize: isProduction,
        sourceMap: !isProduction,
      }),
    ],
  },
];

export default defineConfig(config);
