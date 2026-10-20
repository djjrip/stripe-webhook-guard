// Synthetic remediated pattern example only; configure Stripe and persistent idempotency for your app.
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const rawBody = await request.text();
  const signature = request.headers.get('stripe-signature');
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    return new Response('Missing webhook signature configuration', { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch {
    return new Response('Invalid webhook signature', { status: 400 });
  }

  // A real endpoint must also implement durable, concurrency-safe idempotency
  // before performing any payment fulfillment side effects.
  if (!event.id || !event.type) {
    return new Response('Invalid event', { status: 400 });
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
}
