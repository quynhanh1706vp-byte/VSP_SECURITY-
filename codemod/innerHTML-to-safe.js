#!/usr/bin/env node
/**
 * innerHTML codemod — thay 3 loại assignment:
 *
 *   1. el.innerHTML = ''                 →  el.replaceChildren()
 *   2. el.innerHTML = "literal text"     →  el.textContent = "literal text"
 *   3. el.innerHTML = someVar            →  el.innerHTML = DOMPurify.sanitize(someVar)
 *
 * Usage:
 *   node codemod/innerHTML-to-safe.js <file-or-dir> [--dry-run] [--write]
 *
 * Ví dụ:
 *   node codemod/innerHTML-to-safe.js panels/correlation.html --dry-run
 *   node codemod/innerHTML-to-safe.js panels/ --write
 *
 * CẢNH BÁO: Codemod AST-light, dùng regex. Review kỹ diff trước khi commit!
 * Không chạy trên file đã commit quan trọng mà chưa có test suite.
 */

const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: node innerHTML-to-safe.js <file-or-dir> [--dry-run] [--write]');
  process.exit(1);
}

const DRY = args.includes('--dry-run') || !args.includes('--write');
const target = args.find(a => !a.startsWith('--'));

const stats = { files: 0, changed: 0, empty: 0, literal: 0, sanitize: 0, skipped: 0 };

function transform(src, filename) {
  let out = src;
  let changed = false;

  // Regex lưu ý: \s* cho phép 0 space giữa innerHTML và =
  // Sự thật: nhiều code VSP viết `el.innerHTML=value` (no space)

  // 1. el.innerHTML = ''  hoặc = ""  →  el.replaceChildren()
  out = out.replace(
    /(\w+(?:\.\w+|\[[^\]]+\])*|document\.getElementById\([^)]+\))\.innerHTML\s*=\s*(['"])\2\s*;?/g,
    (m, el) => {
      stats.empty++;
      changed = true;
      return `${el}.replaceChildren();`;
    }
  );

  // 2. el.innerHTML = "some literal string" (không chứa < hoặc >)
  out = out.replace(
    /(\w+(?:\.\w+|\[[^\]]+\])*|document\.getElementById\([^)]+\))\.innerHTML\s*=\s*(['"])([^'"<>]*?)\2\s*;?/g,
    (m, el, q, str) => {
      if (str.length === 0) return m; // đã handle ở trên
      stats.literal++;
      changed = true;
      return `${el}.textContent = ${q}${str}${q};`;
    }
  );

  // 3. el.innerHTML = <expression>  →  wrap DOMPurify
  //    Match cả: el.innerHTML=X, el.innerHTML = X, với X là mọi thứ tới ; hoặc newline
  out = out.replace(
    /(\w+(?:\.\w+|\[[^\]]+\])*|document\.getElementById\([^)]+\))\.innerHTML\s*=\s*((?!DOMPurify\.sanitize)[^;\n]+?)\s*;/g,
    (m, el, expr) => {
      const exprTrim = expr.trim();
      // Skip nếu đã sanitize, hoặc là string literal đơn giản
      if (exprTrim.includes('DOMPurify.sanitize')) return m;
      if (/^(['"`])[^<>'"`]*\1$/.test(exprTrim)) return m; // string literal không HTML

      stats.sanitize++;
      changed = true;
      return `${el}.innerHTML = DOMPurify.sanitize(${exprTrim});`;
    }
  );

  return { out, changed };
}

function processFile(fp) {
  if (!/\.(html|js|jsx|ts|tsx)$/.test(fp)) return;

  stats.files++;
  const src = fs.readFileSync(fp, 'utf8');
  const { out, changed } = transform(src, fp);

  if (!changed) {
    stats.skipped++;
    return;
  }

  stats.changed++;
  const before = (src.match(/\.innerHTML\s*=/g) || []).length;
  const after = (out.match(/\.innerHTML\s*=/g) || []).length;
  console.log(`  ${DRY ? '[DRY]' : '[WRITE]'} ${fp}  innerHTML: ${before} → ${after}`);

  if (!DRY) {
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
console.log(` innerHTML codemod (${DRY ? 'DRY RUN' : 'WRITE MODE'})`);
console.log(` Target: ${target}`);
console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

walk(target);

console.log('');
console.log(`Files scanned:     ${stats.files}`);
console.log(`Files changed:     ${stats.changed}`);
console.log(`  empty strings:   ${stats.empty}  → replaceChildren()`);
console.log(`  literals:        ${stats.literal}  → textContent`);
console.log(`  expressions:     ${stats.sanitize}  → DOMPurify.sanitize()`);
console.log('');

if (DRY) {
  console.log('⚠  DRY RUN — no files modified. Re-run with --write to apply.');
} else {
  console.log('✓ Changes written. Review with: git diff');
  console.log('');
  console.log('NEXT STEPS:');
  console.log('  1. Import DOMPurify in affected files:');
  console.log('     <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.9/purify.min.js"></script>');
  console.log('  2. Run tests (nếu có).');
  console.log('  3. Smoke-test UI trên browser thật.');
  console.log('  4. Commit with: sec(ui): SEC-006 codemod innerHTML → safe alternatives');
}
