import express from "express";
import Session from "express-session";
import cors from "cors";
// @ts-ignore
import { ErrorTypes, generateNonce, SiweMessage } from "siwe";

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(
  Session({
    name: "siwe-boilerplate",
    secret: "siwe-boilerplate-secret",
    resave: true,
    saveUninitialized: false,
    cookie: { secure: false, sameSite: "lax" },
  })
);

app.get("/auth/nonce", async (req, res) => {
  if (!req.session.nonce) {
    req.session.nonce = generateNonce();
  } else {
    req.session.nonce = generateNonce();
  }

  res.setHeader("Content-Type", "text/plain");

  res.status(200).send(req.session.nonce);
});

app.post("/auth/verify", async (req, res) => {
  try {
    if (!req.body.message) {
      res
        .status(422)
        .json({ message: "Expected prepareMessage object as body." });
      return;
    }

    let message = new SiweMessage(req.body.message);
    const fields = await message.validate(req.body.signature);

    console.log({ fields, sess: req.session });

    if (fields.nonce !== req.session.nonce) {
      res.status(422).json({
        message: `Invalid nonce.`,
      });
      return;
    }

    req.session.siwe = fields;

    if (fields.expirationTime) {
      req.session.cookie.expires = new Date(fields.expirationTime);
    }

    req.session.save(() => res.status(200).send("Success!"));
  } catch (e: any) {
    req.session.siwe = null;
    req.session.nonce = null;

    switch (e) {
      case ErrorTypes.EXPIRED_MESSAGE: {
        req.session.save(() => res.status(440).json({ message: e.message }));
        break;
      }
      case ErrorTypes.INVALID_SIGNATURE: {
        req.session.save(() => res.status(422).json({ message: e.message }));
        break;
      }
      default: {
        req.session.save(() => res.status(500).json({ message: e.message }));
        break;
      }
    }
  }
});

app.get("/auth/logout", (req, res) => {
  // @ts-ignore
  req.session = null;

  if (!req.session?.siwe) {
    res.clearCookie("siwe-boilerplate");

    return res.status(200).send({
      message: "User logged out succcessfully",
    });
  }

  res.status(400).json({ message: "Something went wrong" });
});

app.get("/auth/me", (req, res) => {
  if (!req.session?.siwe) {
    res.status(401).json({ message: "You have to first sign_in" });
    return;
  }

  res.setHeader("Content-Type", "text/plain");
  res.send(req.session.siwe.address);
});

const PORT = 4000;

app.listen(PORT, () =>
  console.log(`🚀 Server ready at: http://localhost:${PORT}`)
);
