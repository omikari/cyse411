const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.disable("x-powered-by");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: crypto.createHash("sha256").update("password123").digest("hex")
  }
];

const sessions = {};

function fastHash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function findUser(username) {
  return users.find((u) => u.username === username);
}

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, await bcrypt.hash("password123", 10));
  if (!match) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  const token = crypto.randomBytes(32).toString("hex");

  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  });

  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});

