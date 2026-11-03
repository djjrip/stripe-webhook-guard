#!/usr/bin/env node
/**
 * Stripe Webhook Reliability Test Pack — $99 Introductory Diagnostic
 * 
 * WHAT THIS IS:
 *   A reproducible set of automated checks that scan a customer's webhook
 *   handler source code for the 5 most common Stripe webhook failure patterns.
 *   It produces a scored report with specific remediation guidance.
 * 
 * WHAT THIS IS NOT:
 *   - A certified security audit or penetration test.
 *   - A production guarantee or compliance certification.
 *   - An "exactly-once" payment guarantee.
 *   - A replacement for Stripe's own signature verification library.
 * 
 * The scanner uses source-text pattern matching (regex heuristics), NOT
 * full AST analysis. It catches the most common anti-patterns but cannot
 * guarantee detection of all possible vulnerabilities.
 * 
 * DELIVERABLE INCLUDES:
 *   1. This automated scanner run against the client's webhook handler(s).
 *   2. A JSON report with findings, severity, and remediation steps.
 *   3. A written summary document (Markdown) suitable for team review.
 *   4. Vulnerable and remediated reference fixtures for Express and Next.js.
 *   5. Up to 30 minutes of asynchronous written Q&A on findings.
 * 
 * SCOPE BOUNDARY:
 *   - Scans .ts, .js, .tsx, .jsx, .mjs, .cjs files in provided directory.
 *   - Checks for: raw body corruption, missing signature verification,
 *     missing idempotency, synchronous timeout risk, hardcoded secrets,
 *     and Next.js App Router req.json() misuse.
 *   - Does NOT test live endpoints, does NOT run against production traffic,
 *     does NOT inspect databases, does NOT review infrastructure config.
 * 
 * Author: Jayson Quindao — GG Loop LLC
 * License: MIT (scanner code) / Commercial (report and consultation)
 */

import { WebhookAuditor } from '../src/auditor.js';
import * as fs from 'fs';
import * as path from 'path';

interface TestPackReport {
  generatedAt: string;
  targetPath: string;
  scanner: string;
  scannerVersion: string;
  disclaimer: string;
  results: {
    scannedFiles: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    infoIssues: number;
    overallScore: number;
    status: string;
    findings: Array<{
      id: string;
      severity: string;
      title: string;
      description: string;
      recommendation: string;
      file?: string;
      line?: number;
    }>;
  };
  referenceFixtures: string[];
  limitations: string[];
}

function generateReport(targetPath: string): TestPackReport {
  const auditor = new WebhookAuditor();

  if (!fs.existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }

  const auditResult = auditor.auditPath(targetPath);

  return {
    generatedAt: new Date().toISOString(),
    targetPath: path.resolve(targetPath),
    scanner: 'stripe-webhook-guard WebhookAuditor',
    scannerVersion: '1.1.0',
    disclaimer: 'This report is produced by a source-pattern heuristic scanner. It is NOT a certified security audit, penetration test, or production-readiness certification. Findings should be reviewed by a qualified engineer before making production changes.',
    results: {
      scannedFiles: auditResult.scannedFiles,
      criticalIssues: auditResult.criticalIssues,
      highIssues: auditResult.highIssues,
      mediumIssues: auditResult.mediumIssues,
      infoIssues: auditResult.infoIssues,
      overallScore: auditResult.overallScore,
      status: auditResult.status,
      findings: auditResult.findings.map(f => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        description: f.description,
        recommendation: f.recommendation,
        file: f.file,
        line: f.line
      }))
    },
    referenceFixtures: [
      'tests/fixtures/vulnerable-webhook.ts — Express handler with 3 critical flaws',
      'tests/fixtures/remediated-webhook.ts — Express handler with all flaws resolved',
      'tests/fixtures/vulnerable-nextjs-webhook.ts — Next.js App Router using req.json()',
      'tests/fixtures/remediated-nextjs-webhook.ts — Next.js App Router using req.text()'
    ],
    limitations: [
      'Scanner uses regex/source-pattern matching, not TypeScript AST analysis.',
      'Cannot detect runtime-only vulnerabilities (e.g., database race conditions).',
      'Does not test live webhook endpoints or production Stripe traffic.',
      'Does not verify infrastructure configuration (load balancers, CDN, WAF).',
      'The in-memory idempotency store used in tests is not durable or production-safe.',
      'This diagnostic does not establish compliance with PCI-DSS or SOC 2.'
    ]
  };
}

function generateMarkdownSummary(report: TestPackReport): string {
  const statusEmoji = report.results.status === 'PASS' ? '✅' : report.results.status === 'WARN' ? '⚠️' : '❌';

  let md = `# Stripe Webhook Reliability Diagnostic Report

**Generated:** ${report.generatedAt}  
**Target:** \`${report.targetPath}\`  
**Scanner:** ${report.scanner} v${report.scannerVersion}

> ⚠️ **Disclaimer:** ${report.disclaimer}

---

## Summary

| Metric | Value |
| :--- | :--- |
| Files Scanned | ${report.results.scannedFiles} |
| Overall Score | ${report.results.overallScore}/100 |
| Status | ${statusEmoji} ${report.results.status} |
| Critical Issues | ${report.results.criticalIssues} |
| High Issues | ${report.results.highIssues} |
| Medium Issues | ${report.results.mediumIssues} |
| Info Issues | ${report.results.infoIssues} |

---

## Findings

`;

  if (report.results.findings.length === 0) {
    md += 'No issues detected by the pattern scanner. This does not guarantee the absence of vulnerabilities.\n\n';
  } else {
    for (const finding of report.results.findings) {
      const sevBadge = finding.severity === 'CRITICAL' ? '🔴' : finding.severity === 'HIGH' ? '🟠' : finding.severity === 'MEDIUM' ? '🟡' : '🔵';
      md += `### ${sevBadge} ${finding.severity}: ${finding.title}

**ID:** \`${finding.id}\`  
${finding.file ? `**File:** \`${finding.file}\`${finding.line ? ` (line ${finding.line})` : ''}  ` : ''}

**Description:** ${finding.description}

**Recommendation:** ${finding.recommendation}

---

`;
    }
  }

  md += `## Reference Fixtures Included

${report.referenceFixtures.map(f => `- \`${f}\``).join('\n')}

## Scanner Limitations

${report.limitations.map(l => `- ${l}`).join('\n')}

---

**Produced by:** Jayson Quindao — GG Loop LLC  
**Contact:** jquindao1@icloud.com (asynchronous written communication preferred)
`;

  return md;
}

// --- CLI Entry Point ---
const args = process.argv.slice(2);
const targetPath = args[0] || '.';
const outputDir = args[1] || '.';

console.log(`\n🔍 Stripe Webhook Reliability Test Pack — Diagnostic Scanner`);
console.log(`   Target: ${path.resolve(targetPath)}`);
console.log(`   Output: ${path.resolve(outputDir)}\n`);

try {
  const report = generateReport(targetPath);

  // Write JSON report
  const jsonPath = path.join(outputDir, 'webhook-reliability-report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  console.log(`📊 JSON Report:    ${jsonPath}`);

  // Write Markdown summary
  const mdPath = path.join(outputDir, 'webhook-reliability-report.md');
  fs.writeFileSync(mdPath, generateMarkdownSummary(report));
  console.log(`📝 Markdown Report: ${mdPath}`);

  // Console summary
  const statusEmoji = report.results.status === 'PASS' ? '✅' : report.results.status === 'WARN' ? '⚠️' : '❌';
  console.log(`\n${statusEmoji} Score: ${report.results.overallScore}/100 (${report.results.status})`);
  console.log(`   Critical: ${report.results.criticalIssues} | High: ${report.results.highIssues} | Medium: ${report.results.mediumIssues} | Info: ${report.results.infoIssues}`);

  if (report.results.findings.length > 0) {
    console.log(`\n📋 Top Findings:`);
    for (const f of report.results.findings.slice(0, 5)) {
      console.log(`   [${f.severity}] ${f.title}`);
    }
  }

  console.log(`\n✅ Diagnostic complete. Reports saved to ${path.resolve(outputDir)}\n`);
} catch (err: any) {
  console.error(`❌ Error: ${err.message}`);
  process.exit(1);
}
