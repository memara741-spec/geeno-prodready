"use client";

// Fallback card form for customers who cannot use the hosted checkout.
export function CardForm() {
  return (
    <form action="/api/pay" method="post">
      <label htmlFor="cardNumber">Card number</label>
      <input id="cardNumber" name="cardNumber" inputMode="numeric" />
      <label htmlFor="expiry">Expiry</label>
      <input id="expiry" name="expiry" />
      <label htmlFor="cvc">CVC</label>
      <input id="cvc" name="cvc" />
      <button type="submit">Pay</button>
    </form>
  );
}
