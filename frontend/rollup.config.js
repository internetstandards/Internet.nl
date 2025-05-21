import terser from "@rollup/plugin-terser";
import postcss from "rollup-plugin-postcss";
import { defineConfig } from "rollup";
import fs from "fs";
import path from "path";

const isProduction = process.env.NODE_ENV === "production";
const outputDir = process.env.OUTPUT_DIR ?? "dist";

// Plugin to delete the dist folder before starting a new build
const deleteOutputDir = {
  name: "delete-output-dir",
  buildStart() {
    if (fs.existsSync(outputDir)) {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }
  },
};

// Plugin to clean up dist/css/index.js after the build
const cleanupIndexJs = {
  name: "cleanup-index-js",
  closeBundle() {
    const indexJsPath = path.join(outputDir, "css", "index.js");
    if (fs.existsSync(indexJsPath)) {
      fs.unlinkSync(indexJsPath);
    }
  },
};

// Create config for each file
const config = [
  // JavaScript bundle
  {
    input: "src/index.js",
    output: {
      format: "es",
      sourcemap: !isProduction,
      dir: outputDir + "/js",
      manualChunks: {
        base: [
          "src/js/base/header.js",
          "src/js/base/theme.js",
          "src/js/base/language-switch.js",
          "src/js/base/detect-browser-font-size.js",
          "src/js/base/initial.js",
        ],
        results: [
          "src/js/pages/results/copy-link.js",
          "src/js/pages/results/results.js",
        ],
        connection: ["src/js/pages/connection/connection.js"],
        probe: ["src/js/pages/probe/probe.js"],
        "components/card-list": ["src/js/components/card-list/load-more.js"],
        "components/carousel": ["src/js/components/carousel/carrousel.js"],
        "components/meter": ["src/js/components/meter/result-meter.js"],
        "components/action-card": [
          "src/js/components/action-card/action-card-fallback.js",
        ],
      },
      chunkFileNames: "[name]-min.js",
    },
    plugins: [
      deleteOutputDir,
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
    ],
  },
  // CSS bundle
  {
    input: "src/index.css",
    output: {
      dir: outputDir + "/css",
      assetFileNames: (assetInfo) => {
        // Keep original filename for CSS files
        if (assetInfo.name.endsWith(".css")) {
          return "[name]-min.css";
        }
      },
    },
    plugins: [
      postcss({
        extract: true,
        minimize: isProduction,
        sourceMap: !isProduction,
        inject: false,
        modules: false,
      }),
      cleanupIndexJs,
    ],
  },
];

export default defineConfig(config);
