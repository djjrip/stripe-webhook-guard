import express from 'express';

const app = express();
app.use(express.json()); // Bug 1: Parses body, destroying raw buffer needed for HMAC

// Bug 2: Missing signature verification
// Bug 3: Missing database idempotency
app.post('/webhook', async (req, res) => {
  const event = req.body;
  if (event.type === 'checkout.session.completed') {
    // Fulfill order without checking if event was already processed
    console.log('Order fulfilled for:', event.data.object.id);
  }
  res.status(200).send({ received: true });
});
