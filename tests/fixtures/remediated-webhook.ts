import express from 'express';
import { StripeWebhookGuard } from '../../src/index.js';

const app = express();
const guard = new StripeWebhookGuard({
  webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_mock_secret_key_fixed'
});

// Remediation 1: Retain raw Buffer on the webhook route so HMAC SHA-256 matches
app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const signature = req.headers['stripe-signature'] as string;
    
    // Remediation 2 & 3: Signature verification and atomic idempotency via StripeWebhookGuard
    const outcome = await guard.processEvent(req.body.toString(), signature);

    if (outcome.status === 'SIGNATURE_FAILED') {
      return res.status(400).send('Invalid webhook signature');
    }

    if (outcome.status === 'DUPLICATE_IGNORED') {
      return res.status(200).send({ received: true, note: 'duplicate_suppressed' });
    }

    return res.status(200).send({ received: true, eventId: outcome.eventId });
  }
);
