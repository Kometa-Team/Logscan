const js = require("@eslint/js");
const globals = require("globals");

const rules = {
  ...js.configs.recommended.rules,
  "no-unused-vars": ["error", { args: "none", ignoreRestSiblings: true }],
  "no-shadow": "error",
  "no-implied-eval": "error",
  "no-var": "error",
  "prefer-const": "error",
  eqeqeq: ["error", "always", { null: "ignore" }],
};

module.exports = [
  {
    files: ["logscan_web/static/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "script",
      globals: globals.browser,
    },
    rules,
  },
  {
    files: ["tests/**/*.cjs", "eslint.config.cjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: globals.node,
    },
    rules,
  },
];
