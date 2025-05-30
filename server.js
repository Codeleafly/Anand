require('dotenv').config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const winston = require("winston");
const { GoogleGenerativeAI } = require("@google/generative-ai");

// === Logger Setup ===
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error",
      maxsize: 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(logDir, "combined.log"),
      maxsize: 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.Console(),
  ],
});

// === Constants & Env Vars ===
const ENCRYPTED_API_FILE = path.join(__dirname, "encrypted.api-secure-00-qwertyzz00-un-guessable-.enc+encryption.app...AAdG");
const RUNTIME_FLAG_FILE = path.join(__dirname, "encrypt.runtime.hhhtt");

const MAX_REQUESTS_PER_DAY = 50;

const app = express();
const PORT = process.env.PORT || 3000;

// === ENV Vars ===
const ENC_KEY_RAW = process.env.ENCRYPTION_KEY || "";
const GOOGLE_API_KEY_RAW = process.env.GOOGLE_API_KEY || "";
const FIRST_USER_PASSWORD = process.env.FIRST_USER_PASSWORD || "";

if (!ENC_KEY_RAW || ENC_KEY_RAW.length > 32) {
  logger.error("Invalid ENCRYPTION_KEY in .env (must be max 32 chars)");
  process.exit(1);
}
if (!GOOGLE_API_KEY_RAW) {
  logger.error("Missing GOOGLE_API_KEY in .env");
  process.exit(1);
}
if (!FIRST_USER_PASSWORD) {
  logger.error("Missing FIRST_USER_PASSWORD in .env");
  process.exit(1);
}

// === Prepare Key ===
function prepareKey(key) {
  const buf = Buffer.alloc(32, 0);
  const keyBuf = Buffer.from(key);
  keyBuf.copy(buf);
  return buf;
}
const ENC_KEY = prepareKey(ENC_KEY_RAW);

// === Encrypt / Decrypt ===
function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + encrypted;
}

function decrypt(encryptedText, key) {
  const iv = Buffer.from(encryptedText.slice(0, 32), "hex");
  const encrypted = encryptedText.slice(32);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// === Load API Key ===
function loadAPIKey() {
  if (!fs.existsSync(RUNTIME_FLAG_FILE)) {
    const encryptedKey = encrypt(GOOGLE_API_KEY_RAW, ENC_KEY);
    fs.writeFileSync(ENCRYPTED_API_FILE, encryptedKey);
    fs.writeFileSync(RUNTIME_FLAG_FILE, "ENCRYPTED: YES");
    logger.info("Google API key encrypted and saved for first-time setup.");
    return GOOGLE_API_KEY_RAW;
  } else {
    const encryptedKey = fs.readFileSync(ENCRYPTED_API_FILE, "utf-8");
    return decrypt(encryptedKey, ENC_KEY);
  }
}

const API_KEY = loadAPIKey();
const ai = new GoogleGenerativeAI(API_KEY);

// ✅ === CORS Fix ===
const allowedOrigins = [
  "http://localhost:3000",
  "https://anand-vdgu.onrender.com",              // Tumhara backend URL
  "https://htmlcssjsvirsion.tiiny.site"            // Tumhara frontend code editor
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  }
}));

app.use(bodyParser.json());
app.use(express.static("public"));

// === System Prompt ===
const SYSTEM_PROMPT_PATH = path.join(__dirname, "system.instruction.prompt");
let systemPromptText = `You are Anand, an AI assistant developed and trained by ABC, built with the help of Smart Tell Line.`;

if (fs.existsSync(SYSTEM_PROMPT_PATH)) {
  systemPromptText = fs.readFileSync(SYSTEM_PROMPT_PATH, "utf-8");
}

// === User Auth + Chat Setup ===
let userHistories = {};
let requestCounter = {};

function resetCountersDaily() {
  requestCounter = {};
  setTimeout(resetCountersDaily, 24 * 60 * 60 * 1000);
}
resetCountersDaily();

app.post("/chat", async (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message) {
    logger.warn("Invalid input received.");
    return res.status(400).json({ reply: "Invalid input" });
  }

  if (!userHistories[userId] && message !== FIRST_USER_PASSWORD) {
    logger.warn(`Unauthorized access attempt by ${userId}`);
    return res.status(403).json({ reply: "Unauthorized access. Provide password." });
  }

  // New user, correct password
  if (!userHistories[userId] && message === FIRST_USER_PASSWORD) {
    const model = ai.getGenerativeModel({
      model: "gemini-2.5-flash-preview-05-20",
      generationConfig: { temperature: 1.0, topK: 1, topP: 1 },
      systemInstruction: { role: "system", parts: [{ text: systemPromptText }] },
    });
    const chat = model.startChat({ history: [] });
    userHistories[userId] = { model, chat };
    requestCounter[userId] = 0;
    logger.info(`User ${userId} authenticated with password.`);
    return res.json({ reply: "Access granted. You can now start chatting." });
  }

  if (requestCounter[userId] >= MAX_REQUESTS_PER_DAY) {
    logger.warn(`User ${userId} exceeded daily request limit.`);
    return res.status(429).json({ reply: "Rate limit exceeded for today." });
  }

  try {
    requestCounter[userId]++;
    const result = await userHistories[userId].chat.sendMessage(message);
    res.json({ reply: result.response.text() });
  } catch (err) {
    logger.error(`Chat error: ${err.message}`);
    res.status(500).json({ reply: "Anand is currently unavailable." });
  }
});

app.listen(PORT, () => {
  logger.info(`Anand AI running securely on http://localhost:${PORT}`);
});
