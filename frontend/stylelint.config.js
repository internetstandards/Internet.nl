// used by `make lint` and `make fix`
export default {
  extends: "stylelint-config-standard",
  rules: {
    // reports unrelated rules of different components that end in the same selector
    "no-descending-specificity": null,
    // the current scroll marker of the carousel, which stylelint does not know yet
    "selector-pseudo-class-no-unknown": [true, { ignorePseudoClasses: ["target-current"] }],
  },
};
