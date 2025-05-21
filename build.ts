import type { BuildConfig } from 'bun'
import dts from 'bun-plugin-dts'
import fs from 'node:fs/promises'
import path from 'node:path'

const defaultLibraryConfig: BuildConfig = {
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  external: ['@bsv/sdk'],
  target: 'node'
}

const cliConfig: BuildConfig = {
  entrypoints: ['./cli/bbackup.ts'],
  outdir: './dist/cli',
  external: ['@bsv/sdk', 'commander'],
  format: 'esm',
  target: 'node',
  naming: "[name].js"
}

await Promise.all([
  Bun.build({
    ...defaultLibraryConfig,
    plugins: [dts()],
    format: 'esm',
    naming: "[dir]/[name].js",
  }),
  Bun.build({
    ...defaultLibraryConfig,
    format: 'cjs',
    naming: "[dir]/[name].cjs",
  })
])

const cliBuildResult = await Bun.build(cliConfig)

if (cliBuildResult.success) {
  for (const output of cliBuildResult.outputs) {
    const outputPath = output.path
    if (path.basename(outputPath) === 'bbackup.js') {
      try {
        let content = await fs.readFile(outputPath, 'utf-8')
        if (!content.startsWith('#!/usr/bin/env node')) {
          content = `#!/usr/bin/env node\n${content}`
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
