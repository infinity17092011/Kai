require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const {
  MONGODB_URI,
  JWT_SECRET,
  GROQ_API_KEY,
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_WEBHOOK_ID,
  PAYPAL_ENV,
  ALLOWED_ORIGIN,
  PORT
} = process.env;

const PAYPAL_BASE =
  PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// Fail loudly at startup if something essential is missing, rather than
// mysteriously failing on the first real request.
["MONGODB_URI", "JWT_SECRET", "GROQ_API_KEY", "PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET"].forEach((key) => {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
  }
});

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: ALLOWED_ORIGIN || "*"
  })
);

/* ============================= DATABASE ============================= */

mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  subscribed: { type: Boolean, default: false },
  paypalSubscriptionId: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

/* ============================== HELPERS =============================== */

function signToken(user) {
  return jwt.sign({ sub: user._id.toString() }, JWT_SECRET, { expiresIn: "30d" });
}

// Verifies the JWT and loads the current user fresh from the DB on every
// request, so subscription status is always up to date (not cached in the token).
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing token." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: "Account no longer exists." });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function requireSubscription(req, res, next) {
  if (!req.user.subscribed) {
    return res.status(402).json({ error: "Subscription required." });
  }
  next();
}

let cachedPaypalToken = null;
let cachedPaypalTokenExpiry = 0;

async function getPaypalAccessToken() {
  if (cachedPaypalToken && Date.now() < cachedPaypalTokenExpiry) {
    return cachedPaypalToken;
  }

  const creds = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");
  const response = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${creds}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error_description || "Failed to get PayPal access token.");
  }

  cachedPaypalToken = data.access_token;
  cachedPaypalTokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  return cachedPaypalToken;
}

async function getPaypalSubscription(subscriptionId) {
  const accessToken = await getPaypalAccessToken();
  const response = await fetch(`${PAYPAL_BASE}/v1/billing/subscriptions/${subscriptionId}`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || "Failed to fetch subscription from PayPal.");
  }
  return data;
}

/* ============================ AUTH ROUTES ============================ */

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

app.post("/api/signup", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    if (!isValidEmail(email) || password.length < 8) {
      return res.status(400).json({ error: "Enter a valid email and an 8+ character password." });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: "An account with that email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });

    res.json({ token: signToken(user) });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Something went wrong creating your account." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    res.json({ token: signToken(user) });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Something went wrong signing you in." });
  }
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    userId: req.user._id.toString(),
    email: req.user.email,
    subscribed: req.user.subscribed
  });
});

/* ========================= PAYPAL SUBSCRIPTION ========================= */

// Called right after the PayPal button's onApprove fires. This gives the
// user instant access. The webhook below is the authoritative long-term
// source of truth (handles renewals, cancellations, disputes, etc).
app.post("/api/paypal/confirm", requireAuth, async (req, res) => {
  try {
    const { subscriptionID } = req.body;
    if (!subscriptionID) {
      return res.status(400).json({ error: "Missing subscriptionID." });
    }

    const subscription = await getPaypalSubscription(subscriptionID);

    if (subscription.status !== "ACTIVE") {
      return res.status(402).json({ error: `Subscription status is ${subscription.status}, not active.` });
    }

    req.user.subscribed = true;
    req.user.paypalSubscriptionId = subscriptionID;
    await req.user.save();

    res.json({ subscribed: true });
  } catch (err) {
    console.error("PayPal confirm error:", err);
    res.status(500).json({ error: "Could not verify subscription with PayPal." });
  }
});

// PayPal calls this directly (server-to-server) on subscription lifecycle
// events. Point a webhook at https://YOUR_BACKEND/api/paypal/webhook in the
// PayPal developer dashboard, subscribed to at least:
//   BILLING.SUBSCRIPTION.ACTIVATED, BILLING.SUBSCRIPTION.CANCELLED,
//   BILLING.SUBSCRIPTION.EXPIRED, BILLING.SUBSCRIPTION.SUSPENDED
app.post("/api/paypal/webhook", async (req, res) => {
  try {
    const accessToken = await getPaypalAccessToken();

    const verifyResponse = await fetch(`${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        auth_algo: req.headers["paypal-auth-algo"],
        cert_url: req.headers["paypal-cert-url"],
        transmission_id: req.headers["paypal-transmission-id"],
        transmission_sig: req.headers["paypal-transmission-sig"],
        transmission_time: req.headers["paypal-transmission-time"],
        webhook_id: PAYPAL_WEBHOOK_ID,
        webhook_event: req.body
      })
    });

    const verifyData = await verifyResponse.json();
    if (verifyData.verification_status !== "SUCCESS") {
      console.warn("PayPal webhook signature verification failed.");
      return res.status(400).send("Signature verification failed.");
    }

    const event = req.body;
    const resource = event.resource || {};
    const subscriptionId = resource.id;

    if (!subscriptionId) {
      return res.status(200).send("No subscription id in event, ignoring.");
    }

    const activatingEvents = ["BILLING.SUBSCRIPTION.ACTIVATED"];
    const deactivatingEvents = [
      "BILLING.SUBSCRIPTION.CANCELLED",
      "BILLING.SUBSCRIPTION.EXPIRED",
      "BILLING.SUBSCRIPTION.SUSPENDED"
    ];

    if (activatingEvents.includes(event.event_type)) {
      await User.findOneAndUpdate(
        { paypalSubscriptionId: subscriptionId },
        { subscribed: true }
      );
    } else if (deactivatingEvents.includes(event.event_type)) {
      await User.findOneAndUpdate(
        { paypalSubscriptionId: subscriptionId },
        { subscribed: false }
      );
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error("PayPal webhook error:", err);
    res.status(500).send("Webhook handling failed.");
  }
});

/* ================================ CHAT ================================ */

app.post("/api/chat", requireAuth, requireSubscription, async (req, res) => {
  try {
    const { mode, message } = req.body;
    const trimmed = (message || "").trim();

    if (!trimmed) {
      return res.status(400).json({ error: "Message is required." });
    }

    const systemPrompt =
      `You are Kai, a skilled social texting assistant. The user's selected style is: ${mode || "Smooth"}. ` +
      `Help the user create a natural, confident reply to the message they provide. ` +
      `Keep the reply appropriate, conversational, and realistic. ` +
      `Return the suggested reply first. You may briefly explain why it works if useful.`;

    const groqResponse = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${GROQ_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Message to reply to:\n${trimmed}` }
        ],
        temperature: 0.8,
        max_tokens: 400
      })
    });

    const data = await groqResponse.json();

    if (!groqResponse.ok) {
      throw new Error(data.error?.message || "Groq request failed.");
    }

    const answer = data.choices?.[0]?.message?.content?.trim() || "Kai couldn't cook that one. Try again.";
    res.json({ answer });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "Kai's brain is unavailable right now." });
  }
});

/* ================================ START ================================ */

const port = PORT || 3000;
app.listen(port, () => console.log(`Kai backend listening on port ${port}`));
