#!/usr/bin/env python3
"""
classify-innerhtml-high.py — Phân loại 53 HIGH innerHTML sites thành 3 buckets.

Buckets:
  TEXT       — innerHTML = "static string with no HTML" → thay bằng textContent
  STRUCTURED — innerHTML = `<div>...${fixedVar}...</div>` với data an toàn → createElement
  DYNAMIC    — innerHTML = `...${userInput}...` với data có thể tainted → DOMPurify

Output:
  docs/sprint4/innerhtml-high-classified.csv
  Summary ra stdout.

Decision logic:
  - Nếu template literal chỉ có text/number interpolation → TEXT
  - Nếu có HTML tags + data static hoặc typed → STRUCTURED
  - Nếu có data từ API/user/unknown source → DYNAMIC (safe default)
"""

import re
import csv
import subprocess
from pathlib import Path
from collections import Counter


def get_hits():
    """Grep all HIGH innerHTML (template literal) sites."""
    result = subprocess.run(
        ['grep', '-rnE', r'\.innerHTML\s*=\s*`', 'static/'],
        capture_output=True, text=True
    )
    hits = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        # format: file:line:content
        parts = line.split(':', 2)
        if len(parts) < 3:
            continue
        hits.append({'file': parts[0], 'line': int(parts[1]), 'content': parts[2]})
    return hits


def classify(snippet):
    """Classify a single innerHTML hit.

    Returns: (bucket, reason)
    """
    s = snippet.strip()

    # Extract the template literal content
    # Pattern: .innerHTML = `...`
    m = re.search(r'\.innerHTML\s*=\s*`(.*?)`', s, re.DOTALL)
    if not m:
        # Multi-line template literal — inspect the line itself
        template_body = s
    else:
        template_body = m.group(1)

    # Check for HTML tags
    has_html_tags = bool(re.search(r'<[a-z][a-z0-9]*[^>]*>', template_body, re.IGNORECASE))

    # Check for interpolation
    has_interp = '${' in template_body

    # Check what kind of interpolation
    interpolations = re.findall(r'\$\{([^}]+)\}', template_body)

    # Heuristics for dangerous data sources
    dangerous_sources = [
        'user', 'input', 'search', 'query', 'param', 'body',
        'response', 'result', 'data.', 'res.', 'r.',
        '.name', '.title', '.message', '.description', '.note',
        '.content', '.text', '.html', '.value',
        'innerText', 'innerHTML', 'textContent',
        # API-sourced
        'json.', 'fetch', 'api',
    ]

    # Heuristics for safe data sources
    safe_sources = [
        'Math.', 'Date', 'String(',
        'toFixed', 'toLocaleString',
        'length', 'count', 'total',
        '.size', '.duration',
    ]

    def source_risk(var_expr):
        lower = var_expr.lower()
        for d in dangerous_sources:
            if d in lower:
                return 'dangerous'
        for s in safe_sources:
            if s in var_expr:
                return 'safe'
        # Default: treat unknown as dangerous (safer)
        return 'unknown'

    # Decision tree
    if not has_html_tags and not has_interp:
        return ('TEXT', 'no HTML tags, no interpolation — pure static text')

    if not has_html_tags and has_interp:
        # ${var} without tags → should use textContent
        risks = [source_risk(v) for v in interpolations]
        if all(r == 'safe' for r in risks):
            return ('TEXT', f'no HTML, {len(interpolations)} safe interpolation(s)')
        else:
            return ('TEXT', f'no HTML, use textContent regardless of source')

    if has_html_tags and not has_interp:
        return ('STRUCTURED', 'HTML tags but no interpolation — fixed template')

    # has_html_tags AND has_interp
    risks = [source_risk(v) for v in interpolations]

    if all(r == 'safe' for r in risks):
        return ('STRUCTURED', f'HTML + {len(interpolations)} safe interpolation(s) (numeric/date)')

    if any(r == 'dangerous' for r in risks):
        dangerous_vars = [v for v, r in zip(interpolations, risks) if r == 'dangerous']
        return ('DYNAMIC', f'HTML + dangerous source: {dangerous_vars[:3]}')

    # Unknown sources default to DYNAMIC (safer)
    unknown_vars = [v for v, r in zip(interpolations, risks) if r == 'unknown']
    return ('DYNAMIC', f'HTML + unknown source: {unknown_vars[:3]}')


def main():
    hits = get_hits()
    print(f"Scanning {len(hits)} template-literal innerHTML sites...\n")

    classified = []
    bucket_counts = Counter()
    file_bucket = {}  # file -> Counter of buckets

    for hit in hits:
        bucket, reason = classify(hit['content'])
        classified.append({
            **hit,
            'bucket': bucket,
            'reason': reason,
        })
        bucket_counts[bucket] += 1
        file_bucket.setdefault(hit['file'], Counter())[bucket] += 1

    # Write CSV
    out_csv = Path('docs/sprint4/innerhtml-high-classified.csv')
    out_csv.parent.mkdir(exist_ok=True)
    with out_csv.open('w') as f:
        writer = csv.DictWriter(f, fieldnames=['file', 'line', 'bucket', 'reason', 'content'])
        writer.writeheader()
        for row in classified:
            # Truncate content to keep CSV readable
            row['content'] = row['content'].strip()[:200]
            writer.writerow(row)

    # Summary
    print("━━ Bucket distribution ━━")
    total = sum(bucket_counts.values())
    for bucket in ['TEXT', 'STRUCTURED', 'DYNAMIC']:
        count = bucket_counts.get(bucket, 0)
        pct = (count / total * 100) if total else 0
        effort = {'TEXT': '5 min', 'STRUCTURED': '15 min', 'DYNAMIC': '20 min'}[bucket]
        total_effort = count * {'TEXT': 5, 'STRUCTURED': 15, 'DYNAMIC': 20}[bucket]
        print(f"  {bucket:12s} {count:3d} ({pct:5.1f}%)  ~{effort} each = {total_effort} min total")

    print(f"\n  Total estimated effort: {sum(bucket_counts[b] * {'TEXT':5,'STRUCTURED':15,'DYNAMIC':20}.get(b, 0) for b in bucket_counts):.0f} min")

    print("\n━━ Top 10 files ━━")
    sorted_files = sorted(file_bucket.items(), key=lambda x: -sum(x[1].values()))
    for file, buckets in sorted_files[:10]:
        total_f = sum(buckets.values())
        parts = [f"{b}={buckets[b]}" for b in ['TEXT', 'STRUCTURED', 'DYNAMIC'] if buckets.get(b)]
        print(f"  {total_f:3d}  {file}  [{', '.join(parts)}]")

    print(f"\n✓ Full classification: {out_csv}")

    # Sample of each bucket
    print("\n━━ Examples per bucket ━━")
    for bucket in ['TEXT', 'STRUCTURED', 'DYNAMIC']:
        samples = [c for c in classified if c['bucket'] == bucket][:3]
        if samples:
            print(f"\n→ {bucket}:")
            for s in samples:
                content_short = s['content'].strip()[:100]
                print(f"  {s['file']}:{s['line']}  — {s['reason']}")
                print(f"    {content_short}")


if __name__ == '__main__':
    main()
