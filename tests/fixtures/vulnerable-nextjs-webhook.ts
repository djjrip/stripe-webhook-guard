// Vulnerable Next.js App Router Webhook
// Bug: Uses req.json() instead of req.text(), breaking HMAC signature verification
import { NextResponse } from 'next/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_123');

export async function POST(req: Request) {
  const body = await req.json(); // Critical Flaw: parses body instead of raw text
  const signature = req.headers.get('stripe-signature') || '';

  try {
    const event = stripe.webhooks.constructEvent(
      body as any,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
    return NextResponse.json({ received: true });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 400 });
  }
}
