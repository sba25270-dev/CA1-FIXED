const security = require("eslint-plugin-security");

module.exports = [
  security.configs.recommended,
  {
    rules: {
      "security/detect-object-injection": "warn",
      "security/detect-child-process": "error",
      "security/detect-non-literal-fs-filename": "error",
      "security/detect-eval-with-expression": "error"
    }
  }
];
