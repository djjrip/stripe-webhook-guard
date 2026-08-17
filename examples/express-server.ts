/**
 * Example: Zero-Loss Stripe Webhook Handler with Express.js
 */
import { StripeWebhookGuard } from '../src/index.js';

const guard = new StripeWebhookGuard({
  webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_secret'
});

// Register event handler for completed checkouts
guard.on('checkout.session.completed', async (event) => {
  const session = event.data.object as Record<string, unknown>;
  console.log(`💰 Verified Payment Session: ${session.id} for $${Number(session.amount_total) / 100}`);
  // Execute database provisioning / credit assignment here safely (no duplicate risk!)
});

// Register handler for subscription cancellations
guard.on('customer.subscription.deleted', async (event) => {
  const sub = event.data.object as Record<string, unknown>;
  console.log(`⚠️ Subscription Canceled: ${sub.id}`);
});

console.log('StripeWebhookGuard initialized and ready.');
