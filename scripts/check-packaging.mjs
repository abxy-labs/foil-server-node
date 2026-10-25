import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const esm = await import(path.join(__dirname, '..', 'dist', 'index.js'));
const cjs = require(path.join(__dirname, '..', 'dist', 'index.cjs'));

for (const mod of [esm, cjs]) {
  assert.equal(typeof mod.Foil, 'function');
  assert.equal(typeof mod.verifyFoilToken, 'function');
  assert.equal(typeof mod.safeVerifyFoilToken, 'function');
}

// Type-check the published declarations the way a consumer on NodeNext resolution
// sees them, from both an ES module and a CommonJS module.
const consumers = ['consumer.mts', 'consumer.cts'].map((name) => path.join(__dirname, 'packaging', name));
const program = ts.createProgram(consumers, {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  strict: true,
  noEmit: true,
  types: ['node'],
});
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length > 0) {
  console.error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (fileName) => fileName,
    getCurrentDirectory: () => process.cwd(),
    getNewLine: () => '\n',
  }));
  process.exit(1);
}
