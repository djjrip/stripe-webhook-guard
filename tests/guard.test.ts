import { StripeWebhookGuard } from '../src/index.js';
import * as crypto from 'crypto';
import * as assert from 'assert';

async function runTests() {
  console.log('🧪 Starting StripeWebhookGuard test suite...');

  const secret = 'whsec_test_suite_secret_key_12345';
  const guard = new StripeWebhookGuard({ webhookSecret: secret });

  let processedCount = 0;
  guard.on('payment_intent.succeeded', async (event) => {
    processedCount++;
  });

  const payload = JSON.stringify({
    id: 'evt_test_123456789',
    type: 'payment_intent.succeeded',
    created: Math.floor(Date.now() / 1000),
    data: {
      object: {
        id: 'pi_test_123',
        amount: 5000,
        currency: 'usd'
      }
    }
  });

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${payload}`, 'utf8')
    .digest('hex');
  const header = `t=${timestamp},v1=${signature}`;

  // Test 1: First valid execution
  const res1 = await guard.processEvent(payload, header);
  assert.strictEqual(res1.status, 'PROCESSED', 'Expected first event to be PROCESSED');
  assert.strictEqual(processedCount, 1, 'Expected handler to run exactly once');
  console.log('✅ Test 1 Passed: Valid event processed successfully.');

  // Test 2: Replay / Duplicate suppression
  const res2 = await guard.processEvent(payload, header);
  assert.strictEqual(res2.status, 'DUPLICATE_IGNORED', 'Expected duplicate event to be DUPLICATE_IGNORED');
  assert.strictEqual(processedCount, 1, 'Handler MUST NOT run again on duplicate');
  console.log('✅ Test 2 Passed: Duplicate webhook replay suppressed without duplicate execution.');

  // Test 3: Invalid signature rejection
  const invalidHeader = `t=${timestamp},v1=deadbeef00000000000000000000000000000000000000000000000000000000`;
  const res3 = await guard.processEvent(payload, invalidHeader);
  assert.strictEqual(res3.status, 'SIGNATURE_FAILED', 'Expected invalid signature to fail');
  console.log('✅ Test 3 Passed: Tampered/invalid HMAC signature rejected.');

  // Test 4: WebhookAuditor AST scanner on vulnerable vs remediated fixtures
  const auditor = new (await import('../src/auditor.js')).WebhookAuditor();
  const vulnReport = auditor.auditPath('tests/fixtures/vulnerable-webhook.ts');
  assert.strictEqual(vulnReport.status, 'FAIL', 'Expected vulnerable fixture to fail audit');
  assert.strictEqual(vulnReport.criticalIssues, 2, 'Expected 2 critical flaws detected');
  
  const remediatedReport = auditor.auditPath('tests/fixtures/remediated-webhook.ts');
  assert.strictEqual(remediatedReport.status, 'PASS', 'Expected remediated fixture to pass audit');
  assert.strictEqual(remediatedReport.overallScore, 100, 'Expected remediated fixture to score 100/100');
  console.log('✅ Test 4 Passed: Existing Express fixtures produce expected findings.');

  // Test 5: Next.js App Router raw-body pattern heuristic
  const nextVulnerable = auditor.auditPath('tests/fixtures/vulnerable-nextjs-webhook.ts');
  assert.ok(nextVulnerable.findings.some(f => f.id === 'NEXTJS_APP_ROUTER_RAW_BODY_RISK'),
    'Expected parsed-JSON App Router fixture to flag raw-body risk');
  const nextRemediated = auditor.auditPath('tests/fixtures/remediated-nextjs-webhook.ts');
  assert.ok(!nextRemediated.findings.some(f => f.id === 'NEXTJS_APP_ROUTER_RAW_BODY_RISK'),
    'Expected raw-body App Router fixture not to trigger raw-body pattern rule');
  assert.strictEqual(nextRemediated.status, 'PASS', 'Expected the remediated Next.js fixture to pass configured heuristics');
  console.log('✅ Test 5 Passed: Next.js App Router vulnerable/remediated fixtures differ as expected.');

  // Test 6: Missing secret fails closed even if the caller supplies a plausible header.
  let unsignedProcessed = 0;
  const noSecretGuard = new StripeWebhookGuard();
  noSecretGuard.on('payment_intent.succeeded', async () => { unsignedProcessed++; });
  const noSecretResult = await noSecretGuard.processEvent(payload, header);
  assert.strictEqual(noSecretResult.status, 'SIGNATURE_FAILED');
  assert.strictEqual(unsignedProcessed, 0, 'An unconfigured guard must not dispatch unsigned events');
  console.log('✅ Test 6 Passed: Missing signing secret fails closed.');

  // Test 7: Missing Stripe-Signature header fails closed.
  let missingHeaderProcessed = 0;
  const noHeaderGuard = new StripeWebhookGuard({ webhookSecret: secret });
  noHeaderGuard.on('payment_intent.succeeded', async () => { missingHeaderProcessed++; });
  const noHeaderResult = await noHeaderGuard.processEvent(payload);
  assert.strictEqual(noHeaderResult.status, 'SIGNATURE_FAILED');
  assert.strictEqual(missingHeaderProcessed, 0, 'A missing signature must not dispatch the event');
  console.log('✅ Test 7 Passed: Missing signature header fails closed.');

  // Test 8: A failed handler can be retried; completed duplicate suppression remains covered by Test 2.
  const retryGuard = new StripeWebhookGuard({ webhookSecret: secret });
  let retryCalls = 0;
  retryGuard.on('payment_intent.succeeded', async () => {
    retryCalls++;
    if (retryCalls === 1) throw new Error('synthetic transient handler failure');
  });
  const retryPayload = JSON.stringify({
    id: 'evt_retry_test_01',
    type: 'payment_intent.succeeded',
    created: Math.floor(Date.now() / 1000),
    data: { object: { id: 'pi_retry_test_01', amount: 5000, currency: 'usd' } }
  });
  const retryTimestamp = Math.floor(Date.now() / 1000);
  const retrySignature = crypto.createHmac('sha256', secret)
    .update(`${retryTimestamp}.${retryPayload}`, 'utf8').digest('hex');
  const retryHeader = `t=${retryTimestamp},v1=${retrySignature}`;
  const firstAttempt = await retryGuard.processEvent(retryPayload, retryHeader);
  assert.strictEqual(firstAttempt.status, 'HANDLER_ERROR');
  const retryAttempt = await retryGuard.processEvent(retryPayload, retryHeader);
  assert.strictEqual(retryAttempt.status, 'PROCESSED');
  assert.strictEqual(retryCalls, 2, 'Failed event should be eligible for retry once');
  console.log('✅ Test 8 Passed: Failed handler event can retry.');

  console.log('🎉 ALL TESTS PASSED SUCCESSFULLY (8/8)!');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
