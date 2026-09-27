const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database("calculator.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS calculations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    expression TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

app.use(helmet());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

app.post("/api/register", authLimiter, async (req, res) => {

  try {

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "All fields are required"
      });
    }

    if (password.length < 12) {
      return res.status(400).json({
        error: "Password must be at least 12 characters"
      });
    }

    const existing = db.prepare(`
      SELECT id FROM users
      WHERE username = ? OR email = ?
    `).get(username, email);

    if (existing) {
      return res.status(409).json({
        error: "Username or email already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users
      (username, email, password_hash)
      VALUES (?, ?, ?)
    `).run(username, email, passwordHash);

    req.session.userId = result.lastInsertRowid;

    res.json({
      success: true,
      username
    });

  } catch {
    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = db.prepare(`
      SELECT * FROM users
      WHERE email = ?
    `).get(email);

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    req.session.userId = user.id;

    res.json({
      success: true,
      username: user.username
    });

  } catch {
    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.post("/api/logout", (req, res) => {

  req.session.destroy(() => {
    res.json({
      success: true
    });
  });

});

app.get("/api/me", (req, res) => {

  if (!req.session.userId) {
    return res.json({
      loggedIn: false
    });
  }

  const user = db.prepare(`
    SELECT id, username, email
    FROM users
    WHERE id = ?
  `).get(req.session.userId);

  res.json({
    loggedIn: true,
    user
  });

});

app.post("/api/history", requireLogin, (req, res) => {

  const { expression, result } = req.body;

  if (!expression || result === undefined) {
    return res.status(400).json({
      error: "Invalid calculation"
    });
  }

  db.prepare(`
    INSERT INTO calculations
    (user_id, expression, result)
    VALUES (?, ?, ?)
  `).run(
    req.session.userId,
    expression,
    String(result)
  );

  res.json({
    success: true
  });

});

app.get("/api/history", requireLogin, (req, res) => {

  const history = db.prepare(`
    SELECT id, expression, result, created_at
    FROM calculations
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.session.userId);

  res.json(history);

});

app.delete("/api/history/:id", requireLogin, (req, res) => {

  db.prepare(`
    DELETE FROM calculations
    WHERE id = ? AND user_id = ?
  `).run(
    req.params.id,
    req.session.userId
  );

  res.json({
    success: true
  });

});

app.listen(PORT, () => {
  console.log(`3D Pro Calculator running on port ${PORT}`);
});
