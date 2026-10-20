// Synthetic vulnerable example only: do not use in production.
export async function POST(request: Request) {
  const body = await request.json();

  if (body.type === 'checkout.session.completed') {
    // A real implementation must not trust this event before signature verification.
    console.log('Would fulfill session:', body.data?.object?.id);
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
}
