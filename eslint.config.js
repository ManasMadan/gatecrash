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
      // Native app trees. Kotlin and Swift are checked by their own toolchains, and
      // the Gradle and SwiftPM build directories under them contain generated
      // JavaScript — Gradle's HTML test report ships its own report.js — which is
      // neither ours nor lintable.
      //
      // These patterns previously read apps/android and apps/ios, which are not the
      // directory names and so matched nothing at all. It went unnoticed until the
      // Android build produced its first report.
      'apps/backstage-android/**',
      'apps/backstage-ios/**',
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
