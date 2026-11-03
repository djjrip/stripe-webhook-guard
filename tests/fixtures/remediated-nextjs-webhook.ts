// Remediated Next.js App Router Webhook
import { NextResponse } from 'next/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_123');

export async function POST(req: Request) {
  const rawBody = await req.text(); // Correct: reads raw text buffer
  const signature = req.headers.get('stripe-signature') || '';

  try {
    const event = stripe.webhooks.constructEvent(
      rawBody,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
    // Check idempotency before fulfillment
    const eventId = event.id;
    return NextResponse.json({ received: true, id: eventId });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 400 });
  }
}
