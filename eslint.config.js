import security from 'eslint-plugin-security';

export default [security.configs.recommended, {
  rules: {
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
  },
}];
