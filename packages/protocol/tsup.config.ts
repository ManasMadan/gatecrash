import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  // The scanner runs on cheap Android phones with old Chrome builds. es2020 is
  // the floor that still gets optional chaining and BigInt without a polyfill.
  target: 'es2020',
  dts: true,
  sourcemap: true,
  clean: true,
})
