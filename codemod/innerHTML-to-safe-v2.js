#!/usr/bin/env node
/**
 * innerHTML codemod v2 — SAFE version
 *
 * v1 bug: regex broke trên HTML strings chứa ';' trong inline CSS
 * v2 fix: CHỈ handle 2 cases an toàn:
 *   1. el.innerHTML = ''  →  el.replaceChildren()
 *   2. el.innerHTML = "plain text no HTML"  →  el.textContent = "..."
 *
 * KHÔNG tự động wrap DOMPurify.sanitize() nữa.
 * Case innerHTML = <complex expression> cần MANUAL review.
 *
 * Usage:
 *   node codemod/innerHTML-to-safe-v2.js <file-or-dir> [--dry-run] [--write]
 */

const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: node innerHTML-to-safe-v2.js <file-or-dir> [--dry-run] [--write]');
  process.exit(1);
}

const DRY = args.includes('--dry-run') || !args.includes('--write');
const target = args.find(a => !a.startsWith('--'));
const stats = { files: 0, changed: 0, empty: 0, literal: 0, skipped_complex: 0 };

function transform(src) {
  let out = src;
  let changed = false;
  let skippedComplex = 0;

  // CASE 1: el.innerHTML = '' (empty assignment) → el.replaceChildren()
  out = out.replace(
    /(\w+(?:\.\w+|\[[^\]]+\])*|document\.getElementById\([^)]+\))\.innerHTML\s*=\s*(['"])\2\s*;?/g,
    (m, el) => {
      stats.empty++;
      changed = true;
      return `${el}.replaceChildren();`;
    }
  );

  // CASE 2: el.innerHTML = "plain text no HTML" → el.textContent = "..."
  // Chỉ apply khi string không chứa < hoặc >
  out = out.replace(
    /(\w+(?:\.\w+|\[[^\]]+\])*|document\.getElementById\([^)]+\))\.innerHTML\s*=\s*(['"])([^'"<>\n]*?)\2\s*;?/g,
    (m, el, q, str) => {
      if (str.length === 0) return m; // đã handle case 1
      stats.literal++;
      changed = true;
      return `${el}.textContent = ${q}${str}${q};`;
    }
  );

  // CASE 3: el.innerHTML = <anything else> → SKIP, report only
  const remainingMatches = out.match(/\.innerHTML\s*=\s*(?!DOMPurify)[^;]/g);
  if (remainingMatches) {
    skippedComplex = remainingMatches.length;
    stats.skipped_complex += skippedComplex;
  }

  return { out, changed, skippedComplex };
}

function processFile(fp) {
  if (!/\.(html|js|jsx|ts|tsx)$/.test(fp)) return;
  stats.files++;

  const src = fs.readFileSync(fp, 'utf8');
  const { out, changed, skippedComplex } = transform(src);

  if (!changed && skippedComplex === 0) return;
  if (changed) stats.changed++;

  const before = (src.match(/\.innerHTML\s*=/g) || []).length;
  const after = (out.match(/\.innerHTML\s*=/g) || []).length;

  console.log(`  ${DRY ? '[DRY]' : '[WRITE]'} ${fp}`);
  console.log(`           innerHTML: ${before} → ${after} (removed: ${before - after}, skipped complex: ${skippedComplex})`);

  if (!DRY && changed) {
    fs.writeFileSync(fp, out, 'utf8');
  }
}

function walk(p) {
  const stat = fs.statSync(p);
  if (stat.isFile()) {
    processFile(p);
  } else if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(p)) {
      if (entry === 'node_modules' || entry === '.git' || entry === 'dist') continue;
      walk(path.join(p, entry));
    }
  }
}

console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
console.log(` innerHTML codemod v2 (SAFE) — ${DRY ? 'DRY RUN' : 'WRITE MODE'}`);
console.log(` Target: ${target}`);
console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
console.log('');

walk(target);

console.log('');
console.log(`Files scanned:         ${stats.files}`);
console.log(`Files changed:         ${stats.changed}`);
console.log(`  empty strings:       ${stats.empty}  → replaceChildren()`);
console.log(`  plain text:          ${stats.literal}  → textContent`);
console.log(`  complex (skipped):   ${stats.skipped_complex}  ← MANUAL review needed`);
console.log('');

if (stats.skipped_complex > 0) {
  console.log('⚠  Complex innerHTML expressions skipped (safer this way).');
  console.log('   For those: manually add DOMPurify.sanitize() wrap after review.');
}

if (DRY) {
  console.log('');
  console.log('⚠  DRY RUN — no files modified. Re-run with --write to apply.');
}
