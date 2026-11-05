export default {
  plugins: {
    "postcss-import": {},
    "@csstools/postcss-cascade-layers": {
      onImportLayerRule: "warn",
    },
    autoprefixer: {},
    "postcss-preset-env": {
      features: {},
    },
    cssnano: {
      preset: "default",
    },
    "postcss-variable-compress": {},
  },
};
