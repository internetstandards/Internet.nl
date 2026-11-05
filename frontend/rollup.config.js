import terser from "@rollup/plugin-terser";
import postcss from "rollup-plugin-postcss";
import { defineConfig } from "rollup";
import fs from "fs";

const isProduction = process.env.NODE_ENV === "production";
const outputDir = process.env.OUTPUT_DIR ?? "dist";

const cleanupOutputDir = () => ({
  name: "cleanup-output-dir",
  buildStart() {
    // in watch mode only the changed bundle is rebuilt
    if (!this.meta.watchMode && fs.existsSync(outputDir)) {
      fs.rmSync(outputDir, { recursive: true, force: true });
    }
  },
});

// One bundle per script tag. Static files are cached under fixed names, so a
// bundle must not import from another one that may be an older cached version.
const scripts = {
  "theme-init": "src/js/theme-init.js",
  base: "src/js/base.js",
  results: "src/js/results.js",
  connection: "src/js/pages/connection/connection.js",
  probe: "src/js/pages/probe/probe.js",
  "components/card-list": "src/js/components/card-list/load-more.js",
  "components/carousel": "src/js/components/carousel/carrousel.js",
};

const config = [
  {
    input: "src/index.css",
    output: {
      file: `${outputDir}/css/style-min.css`,
    },
    plugins: [
      cleanupOutputDir(),
      postcss({
        extract: true,
        minimize: isProduction,
        sourceMap: !isProduction,
      }),
    ],
  },
  ...Object.entries(scripts).map(([name, input]) => ({
    input,
    output: {
      // theme-init is a classic script, loaded synchronously before rendering
      format: name === "theme-init" ? "iife" : "es",
      sourcemap: !isProduction,
      file: `${outputDir}/js/${name}-min.js`,
    },
    plugins: [isProduction && terser()],
  })),
];

export default defineConfig(config);
