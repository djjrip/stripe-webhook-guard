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
  console.log('✅ Test 4 Passed: WebhookAuditor AST scanner accurately validates vulnerable vs remediated fixtures.');

  console.log('🎉 ALL TESTS PASSED SUCCESSFULLY (4/4)!');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
