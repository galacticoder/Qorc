import globals from 'globals';

export default [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node
      }
    },
    rules: {
      'no-unused-vars': ['error', {
        'vars': 'all',
        'args': 'after-used',
        'ignoreRestSiblings': false,
        'argsIgnorePattern': '^_',
        'varsIgnorePattern': '^_',
        'caughtErrors': 'all',
        'caughtErrorsIgnorePattern': '^_'
      }]
    }
  }
];
