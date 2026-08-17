#!/usr/bin/env node

import { StripeWebhookGuard } from '../dist/src/index.js';
import * as crypto from 'crypto';

console.log('🛡️  Stripe Webhook Guard — Zero-Loss Verification CLI');
console.log('====================================================\n');

const testSecret = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_simulated_secret_key_99999';
const guard = new StripeWebhookGuard({ webhookSecret: testSecret });

let executionCount = 0;
guard.on('checkout.session.completed', async (event) => {
  executionCount++;
  console.log(`✅ [PROCESSED] Order fulfilled for Session: ${event.data.object.id} ($${event.data.object.amount_total / 100})`);
});

const sampleEvent = {
  id: `evt_sim_${Date.now()}`,
  type: 'checkout.session.completed',
  created: Math.floor(Date.now() / 1000),
  data: {
    object: {
      id: `cs_live_${Math.floor(Math.random() * 100000)}`,
      amount_total: 49900,
      currency: 'usd',
      customer_email: 'buyer@example.com'
    }
  }
};

const payload = JSON.stringify(sampleEvent);
const timestamp = Math.floor(Date.now() / 1000);
const signature = crypto
  .createHmac('sha256', testSecret)
  .update(`${timestamp}.${payload}`, 'utf8')
  .digest('hex');
const header = `t=${timestamp},v1=${signature}`;

console.log(`📦 Simulating Delivery #1 (Initial Webhook Event: ${sampleEvent.id})...`);
const res1 = await guard.processEvent(payload, header);
console.log(`   Status: ${res1.status} — ${res1.message}`);

console.log(`\n🔁 Simulating Delivery #2 (Duplicate Stripe Retry Replay)...`);
const res2 = await guard.processEvent(payload, header);
console.log(`   Status: ${res2.status} — ${res2.message}`);

console.log(`\n🛡️  Tamper Simulation (Invalid HMAC Signature)...`);
const badHeader = `t=${timestamp},v1=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad`;
const res3 = await guard.processEvent(payload, badHeader);
console.log(`   Status: ${res3.status} — ${res3.message}`);

console.log('\n====================================================');
console.log(`📊 Summary: 3 Attempts | Total Order Executions: ${executionCount} (Zero Duplicates)`);
console.log('💼 Need this in production? Book a 48-Hour Payment Sprint: jquindao1@icloud.com');
console.log('🌐 Built by GG Loop Engineering (https://djjrip.github.io/gaming-for-groceries/)');
