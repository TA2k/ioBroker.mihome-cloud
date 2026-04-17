import iobrokerEslintConfig from "@iobroker/eslint-config";

export default [
  ...iobrokerEslintConfig,
  {
    languageOptions: {
      globals: {
        describe: "readonly",
        it: "readonly",
        before: "readonly",
        after: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
      },
    },
    rules: {
      indent: ["error", 2, { SwitchCase: 1 }],
      "no-console": "off",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-empty-object-type": "off",
      "no-var": "error",
      "no-trailing-spaces": "error",
      "prefer-const": "error",
      quotes: [
        "error",
        "double",
        { avoidEscape: true, allowTemplateLiterals: true },
      ],
      semi: ["error", "always"],
      "jsdoc/require-jsdoc": "off",
      "jsdoc/require-param-description": "off",
    },
  },
];
