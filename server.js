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

/* ============================ ENVIRONMENT ============================ */

const requiredEnv = [
  "MONGODB_URI",
  "JWT_SECRET",
  "GROQ_API_KEY",
  "PAYPAL_CLIENT_ID",
  "PAYPAL_CLIENT_SECRET",
  "PAYPAL_WEBHOOK_ID"
];

const missingEnv = requiredEnv.filter((key) => !process.env[key]);

if (missingEnv.length > 0) {
  console.error("Missing required environment variables:");
  missingEnv.forEach((key) => console.error(`- ${key}`));
  process.exit(1);
}

if (!["sandbox", "live"].includes(PAYPAL_ENV)) {
  console.error(
    'PAYPAL_ENV must be exactly "sandbox" or "live".'
  );
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  console.error("JWT_SECRET should be at least 32 characters long.");
  process.exit(1);
}

const PAYPAL_BASE =
  PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

const port = Number(PORT) || 3000;

/* ============================== APP ============================== */

const app = express();

app.disable("x-powered-by");

app.use(
  cors({
    origin: ALLOWED_ORIGIN || "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

/* ============================== STATUS ============================== */

app.get("/", (req, res) => {
  res.status(200).json({
    status: "online",
    service: "Kai backend",
    paypal: PAYPAL_ENV,
    timestamp: new Date().toISOString()
  });
});

app.get("/health", (req, res) => {
  const databaseReady =
    mongoose.connection.readyState === 1;

  res.status(databaseReady ? 200 : 503).json({
    status: databaseReady ? "healthy" : "starting",
    database: databaseReady ? "connected" : "not connected",
    timestamp: new Date().toISOString()
  });
});

/* ============================= DATABASE ============================= */

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    subscribed: {
      type: Boolean,
      default: false
    },

    paypalSubscriptionId: {
      type: String,
      default: null
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    versionKey: false
  }
);

const User = mongoose.model("User", userSchema);

/* ============================== HELPERS ============================== */

function signToken(user) {
  return jwt.sign(
    {
      sub: user._id.toString()
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/* ============================ AUTH MIDDLEWARE ============================ */

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Missing token."
    });
  }

  const token = header.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      error: "Missing token."
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        error: "Account no longer exists."
      });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "Invalid or expired token."
    });
  }
}

function requireSubscription(req, res, next) {
  if (!req.user.subscribed) {
    return res.status(402).json({
      error: "Subscription required."
    });
  }

  next();
}

/* ============================ PAYPAL ============================ */

let cachedPaypalToken = null;
let cachedPaypalTokenExpiry = 0;

async function getPaypalAccessToken() {
  if (
    cachedPaypalToken &&
    Date.now() < cachedPaypalTokenExpiry
  ) {
    return cachedPaypalToken;
  }

  const credentials = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch(
    `${PAYPAL_BASE}/v1/oauth2/token`,
    {
      method: "POST",

      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body: "grant_type=client_credentials"
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.error_description ||
        data.message ||
        "Failed to get PayPal access token."
    );
  }

  cachedPaypalToken = data.access_token;

  cachedPaypalTokenExpiry =
    Date.now() +
    Math.max(
      60,
      Number(data.expires_in || 300) - 60
    ) *
      1000;

  return cachedPaypalToken;
}

async function getPaypalSubscription(subscriptionId) {
  if (!subscriptionId) {
    throw new Error("Missing PayPal subscription ID.");
  }

  const accessToken =
    await getPaypalAccessToken();

  const response = await fetch(
    `${PAYPAL_BASE}/v1/billing/subscriptions/${encodeURIComponent(
      subscriptionId
    )}`,
    {
      method: "GET",

      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json"
      }
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message ||
        "Failed to fetch subscription from PayPal."
    );
  }

  return data;
}

/* ============================ SIGNUP ============================ */

app.post("/api/signup", async (req, res) => {
  try {
    const email = String(
      req.body?.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body?.password || ""
    );

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters."
      });
    }

    const existing = await User.findOne({
      email
    });

    if (existing) {
      return res.status(409).json({
        error:
          "An account with that email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    const user = await User.create({
      email,
      passwordHash
    });

    console.log(`New account created: ${email}`);

    res.status(201).json({
      token: signToken(user),
      user: {
        id: user._id.toString(),
        email: user.email,
        subscribed: user.subscribed
      }
    });
  } catch (err) {
    console.error("Signup error:", err);

    if (err.code === 11000) {
      return res.status(409).json({
        error:
          "An account with that email already exists."
      });
    }

    res.status(500).json({
      error:
        "Something went wrong creating your account."
    });
  }
});

/* ============================ LOGIN ============================ */

app.post("/api/login", async (req, res) => {
  try {
    const email = String(
      req.body?.email || ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      req.body?.password || ""
    );

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const user = await User.findOne({
      email
    });

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    res.status(200).json({
      token: signToken(user),
      user: {
        id: user._id.toString(),
        email: user.email,
        subscribed: user.subscribed
      }
    });
  } catch (err) {
    console.error("Login error:", err);

    res.status(500).json({
      error:
        "Something went wrong signing you in."
    });
  }
});

/* ============================== ME ============================== */

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    res.json({
      userId: req.user._id.toString(),
      email: req.user.email,
      subscribed: req.user.subscribed,
      paypalSubscriptionId:
        req.user.paypalSubscriptionId
    });
  }
);

/* ======================== PAYPAL CONFIRM ======================== */

app.post(
  "/api/paypal/confirm",
  requireAuth,
  async (req, res) => {
    try {
      const subscriptionID =
        String(
          req.body?.subscriptionID || ""
        ).trim();

      if (!subscriptionID) {
        return res.status(400).json({
          error: "Missing subscriptionID."
        });
      }

      const subscription =
        await getPaypalSubscription(
          subscriptionID
        );

      console.log(
        "PayPal subscription status:",
        subscription.status
      );

      if (subscription.status !== "ACTIVE") {
        return res.status(402).json({
          error:
            `Subscription status is ${subscription.status}, not active.`
        });
      }

      /*
       * Store the PayPal subscription against
       * the currently authenticated account.
       */
      req.user.subscribed = true;
      req.user.paypalSubscriptionId =
        subscriptionID;

      await req.user.save();

      console.log(
        `Subscription activated for ${req.user.email}`
      );

      res.json({
        subscribed: true,
        subscriptionId: subscriptionID
      });
    } catch (err) {
      console.error(
        "PayPal confirm error:",
        err
      );

      res.status(500).json({
        error:
          "Could not verify subscription with PayPal."
      });
    }
  }
);

/* ========================= PAYPAL WEBHOOK ========================= */

app.post(
  "/api/paypal/webhook",
  async (req, res) => {
    try {
      const requiredHeaders = [
        "paypal-auth-algo",
        "paypal-cert-url",
        "paypal-transmission-id",
        "paypal-transmission-sig",
        "paypal-transmission-time"
      ];

      for (const header of requiredHeaders) {
        if (!req.headers[header]) {
          console.warn(
            `PayPal webhook missing header: ${header}`
          );

          return res.status(400).send(
            "Missing PayPal webhook header."
          );
        }
      }

      const accessToken =
        await getPaypalAccessToken();

      const verifyResponse =
        await fetch(
          `${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`,
          {
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${accessToken}`,

              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              auth_algo:
                req.headers[
                  "paypal-auth-algo"
                ],

              cert_url:
                req.headers[
                  "paypal-cert-url"
                ],

              transmission_id:
                req.headers[
                  "paypal-transmission-id"
                ],

              transmission_sig:
                req.headers[
                  "paypal-transmission-sig"
                ],

              transmission_time:
                req.headers[
                  "paypal-transmission-time"
                ],

              webhook_id:
                PAYPAL_WEBHOOK_ID,

              webhook_event:
                req.body
            })
          }
        );

      const verifyData =
        await verifyResponse.json();

      if (
        !verifyResponse.ok ||
        verifyData.verification_status !==
          "SUCCESS"
      ) {
        console.warn(
          "PayPal webhook signature verification failed."
        );

        return res.status(400).send(
          "Signature verification failed."
        );
      }

      const event = req.body || {};
      const eventType =
        event.event_type || "";

      const resource =
        event.resource || {};

      const subscriptionId =
        resource.id;

      console.log(
        `Verified PayPal webhook: ${eventType}`
      );

      /*
       * Some PayPal events may not contain
       * a subscription ID. They are safely ignored.
       */
      if (!subscriptionId) {
        return res.status(200).send(
          "Webhook received."
        );
      }

      const activatingEvents = [
        "BILLING.SUBSCRIPTION.ACTIVATED"
      ];

      const deactivatingEvents = [
        "BILLING.SUBSCRIPTION.CANCELLED",
        "BILLING.SUBSCRIPTION.EXPIRED",
        "BILLING.SUBSCRIPTION.SUSPENDED"
      ];

      if (
        activatingEvents.includes(
          eventType
        )
      ) {
        const user =
          await User.findOneAndUpdate(
            {
              paypalSubscriptionId:
                subscriptionId
            },
            {
              $set: {
                subscribed: true
              }
            },
            {
              new: true
            }
          );

        if (user) {
          console.log(
            `Subscription activated: ${user.email}`
          );
        } else {
          console.warn(
            `No user found for PayPal subscription ${subscriptionId}`
          );
        }
      } else if (
        deactivatingEvents.includes(
          eventType
        )
      ) {
        const user =
          await User.findOneAndUpdate(
            {
              paypalSubscriptionId:
                subscriptionId
            },
            {
              $set: {
                subscribed: false
              }
            },
            {
              new: true
            }
          );

        if (user) {
          console.log(
            `Subscription deactivated: ${user.email}`
          );
        } else {
          console.warn(
            `No user found for PayPal subscription ${subscriptionId}`
          );
        }
      } else {
        console.log(
          `PayPal event received but no database action is required: ${eventType}`
        );
      }

      return res.status(200).send("OK");
    } catch (err) {
      console.error(
        "PayPal webhook error:",
        err
      );

      return res.status(500).send(
        "Webhook handling failed."
      );
    }
  }
);

/* ================================ CHAT ================================ */

app.post(
  "/api/chat",
  requireAuth,
  requireSubscription,
  async (req, res) => {
    try {
      const mode =
        String(
          req.body?.mode || "Smooth"
        ).trim();

      const message =
        String(
          req.body?.message || ""
        ).trim();

      if (!message) {
        return res.status(400).json({
          error: "Message is required."
        });
      }

      if (message.length > 10000) {
        return res.status(400).json({
          error:
            "Message is too long."
        });
      }

      const systemPrompt =
        `You are Kai, a skilled social texting assistant. ` +
        `The user's selected style is: ${mode}. ` +
        `Help the user create a natural, confident reply to the message they provide. ` +
        `Keep the reply appropriate, conversational, and realistic. ` +
        `Return the suggested reply first. ` +
        `You may briefly explain why it works if useful.`;

      const groqResponse =
        await fetch(
          "https://api.groq.com/openai/v1/chat/completions",
          {
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${GROQ_API_KEY}`,

              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              model:
                "llama-3.3-70b-versatile",

              messages: [
                {
                  role: "system",
                  content:
                    systemPrompt
                },

                {
                  role: "user",
                  content:
                    `Message to reply to:\n${message}`
                }
              ],

              temperature: 0.8,
              max_tokens: 400
            })
          }
        );

      const data =
        await groqResponse.json();

      if (!groqResponse.ok) {
        throw new Error(
          data.error?.message ||
            "Groq request failed."
        );
      }

      const answer =
        data.choices?.[0]?.message?.content?.trim();

      res.json({
        answer:
          answer ||
          "Kai couldn't cook that one. Try again."
      });
    } catch (err) {
      console.error(
        "Chat error:",
        err
      );

      res.status(500).json({
        error:
          "Kai's brain is unavailable right now."
      });
    }
  }
);

/* ========================== ERROR HANDLER ========================== */

app.use((err, req, res, next) => {
  console.error(
    "Unhandled server error:",
    err
  );

  res.status(500).json({
    error: "Internal server error."
  });
});

/* ============================ STARTUP ============================ */

async function startServer() {
  try {
    console.log("Starting Kai backend...");
    console.log(
      `PayPal environment: ${PAYPAL_ENV}`
    );

    await mongoose.connect(
      MONGODB_URI
    );

    console.log(
      "Connected to MongoDB"
    );

    app.listen(
      port,
      "0.0.0.0",
      () => {
        console.log(
          `Kai backend listening on port ${port}`
        );

        console.log(
          `Health check available at /health`
        );
      }
    );
  } catch (err) {
    console.error(
      "Startup failed:",
      err
    );

    process.exit(1);
  }
}

startServer();