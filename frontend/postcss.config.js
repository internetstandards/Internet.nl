export default {
  plugins: {
    "postcss-import": {},
    "@csstools/postcss-cascade-layers": {},
    autoprefixer: {},
    "postcss-preset-env": {
      features: {},
    },
    cssnano: {
      preset: "default",
    },
  },
};
