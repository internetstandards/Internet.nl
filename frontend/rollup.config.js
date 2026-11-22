import terser from "@rollup/plugin-terser";
import postcss from "rollup-plugin-postcss";
import { defineConfig } from "rollup";

const isProduction = process.env.NODE_ENV === "production";
// a static files directory django knows, see STATICFILES_DIRS
const outputDir = "../static_frontend";

// One bundle per script tag. Imports between bundles would not carry the ?v= release
// of static file URLs, so a bundle could import an older cached version of another.
const scripts = {
  "theme-init": "src/js/theme-init.js",
  base: "src/js/base.js",
  results: "src/js/results.js",
  connection: "src/js/pages/connection/connection.js",
  probe: "src/js/pages/probe/probe.js",
  "components/card-list": "src/js/components/card-list/load-more.js",
  "components/carousel": "src/js/components/carousel/carousel.js",
};

const config = [
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
