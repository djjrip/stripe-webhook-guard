"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("../src/index.js");
const crypto = __importStar(require("crypto"));
const assert = __importStar(require("assert"));
async function runTests() {
    console.log('🧪 Starting StripeWebhookGuard test suite...');
    const secret = 'whsec_test_suite_secret_key_12345';
    const guard = new index_js_1.StripeWebhookGuard({ webhookSecret: secret });
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
    console.log('🎉 ALL TESTS PASSED SUCCESSFULLY (3/3)!');
}
runTests().catch(err => {
    console.error('❌ Test failed:', err);
    process.exit(1);
});
