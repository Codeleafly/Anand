// Load environment variables from .env file
require('dotenv').config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const winston = require("winston");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_REQUESTS_PER_DAY = 50;

// --- Logger Setup ---
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

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
            format: winston.format.json()
        }),
        new winston.transports.File({
            filename: path.join(logDir, "combined.log"),
            format: winston.format.json()
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
            )
        }),
    ]
});

// --- Load Environment Variables ---
const ENC_KEY_RAW = process.env.ENCRYPTION_KEY || "";
const GOOGLE_API_KEY_RAW = process.env.GOOGLE_API_KEY || "";
const FIRST_USER_PASSWORD = process.env.FIRST_USER_PASSWORD || "";
const ALLOWED_ORIGINS_ENV = process.env.ALLOWED_ORIGINS?.split(",").map(url => url.trim()) || [];

if (!ENC_KEY_RAW || ENC_KEY_RAW.length < 32 || !GOOGLE_API_KEY_RAW || !FIRST_USER_PASSWORD) {
    logger.error("Missing or invalid .env configuration.");
    process.exit(1);
}

// 32-byte encryption key for aes-256-cbc
const ENC_KEY = Buffer.concat([Buffer.from(ENC_KEY_RAW.slice(0, 32), 'utf8'), Buffer.alloc(32)], 32);

// --- Encrypt/Decrypt Utility ---
function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    return iv.toString("hex") + cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

function decrypt(encrypted, key) {
    const iv = Buffer.from(encrypted.slice(0, 32), "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    return decipher.update(encrypted.slice(32), "hex", "utf8") + decipher.final("utf8");
}

// --- Google AI Setup ---
const ai = new GoogleGenAI({ apiKey: GOOGLE_API_KEY_RAW });

// --- CORS Setup ---
const allowedOrigins = [
    "http://localhost:3000",
    "https://anand-vdgu.onrender.com",
    "https://htmlcssjsvirsion.tiiny.site",
    "https://chatlefy.tiiny.site",
    "https://anand-abc.netlify.app",
    ...ALLOWED_ORIGINS_ENV
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked request from: ${origin}`);
            callback(new Error(`Not allowed by CORS: ${origin}`));
        }
    }
}));

app.use(bodyParser.json());

// ✅ Serve static files from "public" folder
app.use(express.static(path.join(__dirname, "public")));

// --- Load System Prompt ---
const SYSTEM_PROMPT_PATH = path.join(__dirname, "system.instruction.prompt");
let systemPromptText = "You are Anand, an AI assistant. Your goal is to provide helpful and accurate information.";
try {
    if (fs.existsSync(SYSTEM_PROMPT_PATH)) {
        const data = fs.readFileSync(SYSTEM_PROMPT_PATH, "utf8").trim();
        if (data.length > 0) {
            systemPromptText = data;
            logger.info("System prompt loaded from file.");
        } else {
            logger.warn("system.instruction.prompt is empty. Using default.");
        }
    } else {
        logger.warn("system.instruction.prompt not found. Using default.");
    }
} catch (err) {
    logger.error("Failed to load system prompt: " + err.message);
}

// --- In-Memory Store ---
const userHistories = {};
const requestCounter = {};

// --- Reset Rate Limits Every Day ---
function resetCountersDaily() {
    logger.info("Resetting daily request limits.");
    Object.keys(requestCounter).forEach(k => requestCounter[k] = 0);
    setTimeout(resetCountersDaily, 24 * 60 * 60 * 1000);
}
resetCountersDaily();

// --- Chat API ---
app.post("/chat", async (req, res) => {
    const { userId, message } = req.body;

    if (!userId || !message) {
        logger.warn("Invalid chat request: Missing userId or message.");
        return res.status(400).json({ reply: "Invalid input. Provide userId and message." });
    }

    const cleanedMessage = message.trim();
    const isFirstAccess = !userHistories[userId];
    const isCorrectPassword = cleanedMessage === FIRST_USER_PASSWORD;

    if (isFirstAccess) {
        if (!isCorrectPassword) {
            logger.warn(`Unauthorized access from ${userId}. Wrong password.`);
            return res.status(403).json({ reply: "Unauthorized. Provide correct password to begin." });
        }

        try {
            const chat = ai.chats.create({
                model: "gemini-2.5-flash",
                config: {
                    systemInstruction: systemPromptText,
                    temperature: 1.0,
                    topK: 1,
                    topP: 1,
                    thinkingConfig: { thinkingBudget: 0 },
                    tools: [{ googleSearch: {} }, { codeExecution: {} }],
                },
                history: []
            });

            userHistories[userId] = { chat };
            requestCounter[userId] = 0;
            logger.info(`User ${userId} authenticated. Session started.`);
            return res.json({ reply: "Access granted. You can now chat with Anand." });

        } catch (e) {
            logger.error(`Error creating chat for ${userId}: ${e.message}`);
            return res.status(500).json({ reply: "AI unavailable. Try again later." });
        }
    }

    if (requestCounter[userId] >= MAX_REQUESTS_PER_DAY) {
        logger.warn(`User ${userId} hit rate limit.`);
        return res.status(429).json({ reply: "Daily limit reached. Try tomorrow." });
    }

    try {
        requestCounter[userId]++;

        const now = new Date();
        const dateTimeInfo = {
            currentDate: now.toLocaleDateString("en-CA"),
            currentTime: now.toLocaleTimeString("en-GB", { hour12: false }),
            timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timestamp: now.toISOString(),
            currentYear: now.getFullYear(),
            currentDay: now.getDate(),
            currentMonth: now.getMonth() + 1
        };

        const messageForModel = `{"context": ${JSON.stringify(dateTimeInfo)}, "user_message": "${cleanedMessage}"}`;
        const result = await userHistories[userId].chat.sendMessage({ message: messageForModel });
        const reply = result.text || result.response?.text?.() || "No response.";

        logger.info(`User ${userId} got reply: ${reply.slice(0, 80)}...`);
        res.json({ reply });

    } catch (err) {
        logger.error(`Chat error for ${userId}: ${err.message}`);
        res.status(500).json({ reply: "AI error occurred. Please try later." });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    logger.info(`Anand AI server running at http://localhost:${PORT}`);
    logger.info(`Allowed origins: ${allowedOrigins.join(', ')}`);
});
