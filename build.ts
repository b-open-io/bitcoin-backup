import type { BuildConfig } from 'bun'
import fs from 'node:fs/promises'
import path from 'node:path'
import { generateLibraryDeclarations } from './scripts/generate-dts'

const defaultLibraryConfig: BuildConfig = {
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  // fflate must stay external: bundling it inlines fflate's Node ESM, which
  // statically imports `createRequire` from "module" (its worker pool path).
  // That breaks browser/edge bundlers (Turbopack: "Can't resolve 'module'").
  // Externalized, consumers resolve fflate's own browser-safe entry instead.
  external: ['@bsv/sdk', '@1sat/vault', 'fflate'],
  target: 'node'
}

const cliConfig: BuildConfig = {
  entrypoints: ['./cli/bbackup.ts'],
  outdir: './dist/cli',
  external: ['@bsv/sdk', 'commander', '@1sat/vault'],
  format: 'esm',
  target: 'node',
  naming: "[name].js"
}

// Build library (ESM and CJS)
await Promise.all([
  Bun.build({
    ...defaultLibraryConfig,
    format: 'esm',
    naming: "[dir]/[name].js",
  }),
  Bun.build({
    ...defaultLibraryConfig,
    format: 'cjs',
    naming: "[dir]/[name].cjs",
  })
])

// Generate TypeScript declarations
await generateLibraryDeclarations()

const cliBuildResult = await Bun.build(cliConfig)

if (cliBuildResult.success) {
  for (const output of cliBuildResult.outputs) {
    const outputPath = output.path
    if (path.basename(outputPath) === 'bbackup.js') {
      try {
        let content = await fs.readFile(outputPath, 'utf-8')
        if (!content.startsWith('#!/usr/bin/env bun')) {
          content = `#!/usr/bin/env bun\n${content}`
          await fs.writeFile(outputPath, content, 'utf-8')
          console.log(`Added shebang to ${outputPath}`)
        }
      } catch (err) {
        console.error(`Failed to process ${outputPath} for shebang:`, err)
      }
    }
  }
  console.log('CLI build successful.')
} else {
  console.error('CLI build failed:', cliBuildResult.logs)
}

console.log('Build process completed.')
