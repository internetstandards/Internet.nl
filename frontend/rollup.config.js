import terser from "@rollup/plugin-terser";
import postcss from "rollup-plugin-postcss";
import { defineConfig } from "rollup";

const isProduction = process.env.NODE_ENV === "production";
const outputDir = process.env.OUTPUT_DIR ?? "dist";

// Create config for each file
const config = [
  // JavaScript bundle
  {
    input: "js/index.js",
    output: {
      format: "es",
      sourcemap: !isProduction,
      dir: outputDir + "/js",
      manualChunks: {
        base: [
          "js/base/header.js",
          "js/base/theme.js",
          "js/base/language-switch.js",
          "js/base/detect-browser-font-size.js",
          "js/base/initial.js",
        ],
        results: [
          "js/pages/results/copy-link.js",
          "js/pages/results/results.js",
        ],
        connection: ["js/pages/connection/connection.js"],
        probe: ["js/pages/probe/probe.js"],
        "components/card-list": ["js/components/card-list/load-more.js"],
        "components/carousel": ["js/components/carousel/carrousel.js"],
        "components/meter": ["js/components/meter/result-meter.js"],
        "components/action-card": [
          "js/components/action-card/action-card-fallback.js",
        ],
      },
      chunkFileNames: "[name]-min.js",
    },
    plugins: [
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
    input: "css/layers.css",
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
      }),
    ],
  },
];

export default defineConfig(config);
