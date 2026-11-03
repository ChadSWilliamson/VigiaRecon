/**
 * test-email.mjs
 * -----------------------------------------------------------------
 * Sends ONE real test email through Resend, so you can see the
 * alert system actually work before it's wired into anything else.
 *
 * BEFORE RUNNING THIS:
 *   1. Sign up free at resend.com
 *   2. Go to resend.com/api-keys and create a key
 *   3. In your terminal:
 *        export RESEND_API_KEY="your_key_here"
 *
 * HOW TO RUN IT:
 *   node test-email.mjs
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const YOUR_EMAIL = "zonaazulcrconsulting@gmail.com";

async function main() {
  if (!RESEND_API_KEY) {
    console.log("❌ RESEND_API_KEY isn't set. Run the export command first.");
    return;
  }

  console.log(`Sending a test alert to ${YOUR_EMAIL}...\n`);

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Vigía Recon <alerts@vigiarecon.com>",
      to: YOUR_EMAIL,
      subject: "⚠️ Test alert from Vigía Recon",
      text: "If you're reading this, your Vigía Recon alert system works. This is exactly what a real SSL or domain expiration warning will look like.",
    }),
  });

  const data = await res.json();

  if (res.ok) {
    console.log("✅ Sent successfully.");
    console.log(`   Email ID: ${data.id}`);
    console.log("   Check your inbox (and spam folder, just in case).");
  } else {
    console.log(`❌ Failed (status ${res.status})`);
    console.log(`   ${JSON.stringify(data)}`);
  }
}

main();
