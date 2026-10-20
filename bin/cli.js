#!/usr/bin/env node

import { StripeWebhookGuard, WebhookAuditor } from '../dist/index.js';
import * as crypto from 'crypto';
import * as path from 'path';

const args = process.argv.slice(2);
const command = args[0];

function printBanner() {
  console.log('================================================================');
  console.log('🛡️  Stripe Webhook Guard — Diagnostic & Reliability Toolkit');
  console.log('    Built by GG Loop LLC Engineering (https://ggloop.io)');
  console.log('================================================================\n');
}

if (!command || command === '--help' || command === '-h') {
  printBanner();
  console.log('Usage:');
  console.log('  stripe-webhook-guard audit <file-or-dir>   Scan codebase for Stripe webhook flaws');
  console.log('  stripe-webhook-guard verify                Run cryptographic HMAC & idempotency test');
  console.log('\nExamples:');
  console.log('  npx stripe-webhook-guard audit ./src/routes');
  console.log('  npx stripe-webhook-guard audit server.js');
  console.log('\nNeed expert hardening? Contact: Jayson Quindao <jquindao1@icloud.com> | (469) 371-8556');
  console.log('Book 48-Hour Hardening Sprint: https://djjrip.github.io/hire-now.html');
  process.exit(0);
}

if (command === 'audit') {
  const target = args[1] || '.';
  const resolvedTarget = path.resolve(process.cwd(), target);
  printBanner();
  console.log(`🔍 Auditing target: ${resolvedTarget}\n`);

  try {
    const auditor = new WebhookAuditor();
    const report = auditor.auditPath(resolvedTarget);

    console.log(`📁 Files Scanned: ${report.scannedFiles}`);
    console.log(`📊 Reliability Score: ${report.overallScore}/100`);
    console.log(`🚨 Status: ${report.status === 'PASS' ? '✅ PASS' : report.status === 'WARN' ? '⚠️ WARNING' : '❌ CRITICAL FLAWS DETECTED'}\n`);
    console.log(`   Critical Issues: ${report.criticalIssues}`);
    console.log(`   High Issues:     ${report.highIssues}`);
    console.log(`   Medium Issues:   ${report.mediumIssues}`);
    console.log(`   Info Issues:     ${report.infoIssues}\n`);

    if (report.findings.length === 0) {
      console.log('No matched patterns found. This heuristic may miss vulnerabilities; manually review raw-body handling, signature verification, and durable idempotency.');
    } else {
      console.log('----------------------------------------------------------------');
      console.log('DETAILED FINDINGS:');
      console.log('----------------------------------------------------------------');
      report.findings.forEach((f, idx) => {
        const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
        console.log(`\n${idx + 1}. [${icon} ${f.severity}] ${f.title}`);
        if (f.file) console.log(`   File: ${f.file}${f.line ? `:${f.line}` : ''}`);
        console.log(`   Impact: ${f.description}`);
        console.log(`   Fix:    ${f.recommendation}`);
      });
      console.log('\n----------------------------------------------------------------');
      console.log('Scanner output is a starting point for manual review, not proof of production safety:');
      console.log('   Direct: Jayson Quindao | (469) 371-8556 | jquindao1@icloud.com');
      console.log('   Checkout: https://djjrip.github.io/hire-now.html');
      console.log('----------------------------------------------------------------');
    }

    process.exit(report.criticalIssues > 0 ? 1 : 0);
  } catch (err) {
    console.error('❌ Audit failed:', err.message);
    process.exit(1);
  }
} else if (command === 'verify') {
  printBanner();
  console.log('🧪 Verifying HMAC SHA-256 Engine & Memory Idempotency Store...\n');

  const testSecret = 'whsec_verification_key_55555';
  const guard = new StripeWebhookGuard({ webhookSecret: testSecret });
  let processed = 0;

  guard.on('payment_intent.succeeded', async () => {
    processed++;
  });

  const payload = JSON.stringify({
    id: `evt_verify_${Date.now()}`,
    type: 'payment_intent.succeeded',
    created: Math.floor(Date.now() / 1000),
    data: { object: { id: 'pi_verified_99', amount: 49900, currency: 'usd' } }
  });

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto
    .createHmac('sha256', testSecret)
    .update(`${timestamp}.${payload}`, 'utf8')
    .digest('hex');
  const header = `t=${timestamp},v1=${signature}`;

  (async () => {
    const res1 = await guard.processEvent(payload, header);
    console.log(`1. Initial Event Ingestion: ${res1.status} (Processed: ${processed === 1})`);

    const res2 = await guard.processEvent(payload, header);
    console.log(`2. Duplicate Replay Ingestion: ${res2.status} (Suppressed: ${processed === 1})`);

    const badHeader = `t=${timestamp},v1=invalid_signature_hex`;
    const res3 = await guard.processEvent(payload, badHeader);
    console.log(`3. Tampered Payload Ingestion: ${res3.status} (Rejected: true)\n`);

    if (res1.status === 'PROCESSED' && res2.status === 'DUPLICATE_IGNORED' && res3.status === 'SIGNATURE_FAILED') {
      console.log('✅ Local behavior checks passed (3/3). These checks use an in-memory store and synthetic events; they do not establish production readiness.');
    } else {
      console.error('❌ Verification failure detected.');
      process.exit(1);
    }
  })();
} else {
  console.error(`Unknown command: ${command}. Run "stripe-webhook-guard --help" for usage.`);
  process.exit(1);
}
