import globals from 'globals';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import reactHooks from 'eslint-plugin-react-hooks';

export default [
  {
    ignores: [
      'server/**',
      'scripts/**',
      'dist/**',
      'build/**',
      'electron/**',
      'client/**',
      'node_modules/**',
      '**/*.d.ts',
      'test-*.js',
      '*.cjs',
      '*.mjs',
      '**/vite.config.*',
      '**/tailwind.config.*',
      '**/postcss.config.*',
    ],
  },
  {
    files: ['src/**/*.{ts,tsx,js,jsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        project: null,
      },
      globals: {
        ...globals.node,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      'no-undef': 'off',
      'no-empty': 'off',
      'no-console': 'off',
      'no-control-regex': 'off',
      'no-case-declarations': 'off',
      'no-prototype-builtins': 'off',
      '@typescript-eslint/no-var-requires': 'off',
      
      // Aggressive unused code detection
      '@typescript-eslint/no-unused-vars': [
        'error',
        { 
          argsIgnorePattern: '^_', 
          varsIgnorePattern: '^_', 
          ignoreRestSiblings: true,
          caughtErrors: 'all',
          destructuredArrayIgnorePattern: '^_'
        }
      ],
      
      // Detect unreachable code
      'no-unreachable': 'error',
      
      // Detect unused expressions
      'no-unused-expressions': ['error', { 
        allowShortCircuit: true, 
        allowTernary: true, 
        allowTaggedTemplates: true 
      }],
      
      // Detect unused labels
      'no-unused-labels': 'error',
      
      // Detect useless constructors
      'no-useless-constructor': 'off',
      '@typescript-eslint/no-useless-constructor': 'error',
      
      // Detect empty functions (can indicate unused/incomplete code)
      '@typescript-eslint/no-empty-function': ['warn', {
        allow: ['arrowFunctions', 'functions', 'methods', 'constructors']
      }],
    },
  },
];

