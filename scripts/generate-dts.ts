/**
 * TypeScript Declaration Generator
 *
 * This script replaces bun-plugin-dts to avoid compatibility issues with newer @types/bun.
 * It generates .d.ts files using the TypeScript compiler API directly.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import ts from 'typescript';

interface GenerateDtsOptions {
  entrypoint: string;
  outDir: string;
  tsConfigPath?: string;
}

/**
 * Generate TypeScript declaration files using tsc programmatically
 */
async function generateDts({ entrypoint, outDir, tsConfigPath }: GenerateDtsOptions): Promise<void> {
  // Load tsconfig.json
  const configPath = tsConfigPath || path.join(process.cwd(), 'tsconfig.json');
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile);

  if (configFile.error) {
    throw new Error(`Failed to read tsconfig.json: ${configFile.error.messageText}`);
  }

  const parsedConfig = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    path.dirname(configPath)
  );

  // Override compiler options for declaration generation
  const compilerOptions: ts.CompilerOptions = {
    ...parsedConfig.options,
    declaration: true,
    emitDeclarationOnly: true,
    outDir,
    declarationMap: false, // Don't generate .d.ts.map files
    skipLibCheck: true,    // Skip type checking of declaration files
    noEmit: false,         // Override tsconfig's noEmit
    noEmitOnError: false,  // Emit even if there are errors (we'll check diagnostics separately)
  };

  // Create program
  const program = ts.createProgram([entrypoint], compilerOptions);

  // Emit declaration files
  const emitResult = program.emit(
    undefined, // All source files
    undefined, // Default write file
    undefined, // Cancellation token
    true,      // Only emit .d.ts files
    undefined  // Custom transformers
  );

  // Check for errors from our source code
  const sourceDiagnostics = ts
    .getPreEmitDiagnostics(program)
    .concat(emitResult.diagnostics)
    .filter((d) => {
      // Skip errors from node_modules (library type definitions)
      if (d.file?.fileName.includes('node_modules')) return false;

      // Only include actual errors (not warnings)
      return d.category === ts.DiagnosticCategory.Error;
    });

  if (sourceDiagnostics.length > 0) {
    const formatHost: ts.FormatDiagnosticsHost = {
      getCanonicalFileName: (fileName) => fileName,
      getCurrentDirectory: ts.sys.getCurrentDirectory,
      getNewLine: () => ts.sys.newLine,
    };

    const formatted = ts.formatDiagnosticsWithColorAndContext(sourceDiagnostics, formatHost);
    console.error(formatted);

    throw new Error('TypeScript compilation failed');
  }

  console.log(`Generated declarations for ${path.basename(entrypoint)}`);
}

/**
 * Generate declarations for library entrypoint
 */
async function generateLibraryDeclarations() {
  const outDir = path.join(process.cwd(), 'dist');

  // Ensure output directory exists
  await fs.mkdir(outDir, { recursive: true });

  // Generate declarations for main library entry
  await generateDts({
    entrypoint: path.join(process.cwd(), 'src/index.ts'),
    outDir,
  });

  console.log('✓ TypeScript declarations generated successfully');
}

// Run if executed directly
if (import.meta.main) {
  generateLibraryDeclarations().catch((error) => {
    console.error('Failed to generate declarations:', error);
    process.exit(1);
  });
}

export { generateDts, generateLibraryDeclarations };
