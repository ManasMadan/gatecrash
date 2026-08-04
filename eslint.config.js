// @ts-check
import eslint from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      'docs/.vitepress/cache/**',
      '**/*.d.ts',
      // Native app trees. Kotlin and Swift are linted by their own toolchains
      // (ktlint, swift-format) in the mobile CI job.
      'apps/android/**',
      'apps/ios/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // The QR codec and the Bloom filter reader work on raw byte buffers; a
      // bitwise expression on a Uint8Array is the point, not an accident.
      '@typescript-eslint/no-bitwise': 'off',
      // Scanner state arrives from a camera decode and from IndexedDB; both are
      // genuinely unknown until validated by the protocol package.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      // Fire-and-forget is correct for haptics and audio: a failed buzz must
      // never delay the verdict screen.
      '@typescript-eslint/no-floating-promises': ['error', { ignoreVoid: true }],
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
  {
    files: ['apps/*/src/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: { ...reactHooks.configs.recommended.rules },
  },
  {
    files: ['docs/**/*.ts'],
    extends: [tseslint.configs.disableTypeChecked],
  },
  {
    files: ['**/*.{js,mjs,cjs}'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
  },
)
