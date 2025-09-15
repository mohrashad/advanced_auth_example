import { z } from "zod";
import cors from "cors";
import Redis from "ioredis";
import dotenv from "dotenv";
import express from "express";
import bcrypt from "bcryptjs";
import * as jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import cookieParser from "cookie-parser";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
}));

const PORT = Number(process.env.PORT || 4000);
const ACCESS_SECRET = process.env.ACCESS_SECRET || "change_this_access_secret";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "change_this_refresh_secret";
const ACCESS_EXPIRES: any = process.env.ACCESS_EXPIRES || "1m";
const REFRESH_EXPIRES_SECONDS = Number(process.env.REFRESH_EXPIRES_SECONDS || 7 * 24 * 3600); // 7 days
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const COOKIE_NAME = process.env.COOKIE_NAME || "refreshToken";

const redis = new Redis(REDIS_URL);
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
    allowedHeaders: ["Content-Type", "x-csrf-token"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  })
);

const rtjKey = (jti: string) => `rtj:${jti}`; 
const userSessionsKey = (uid: string) => `user:${uid}:sessions`;
const userDeviceKey = (uid: string, did: string) => `user:${uid}:device:${did}`;
const deviceAttemptKey = (uid: string, did: string) => `user:${uid}:device:${did}:refreshAttempts`;


const GETDEL_LUA = `
  local v = redis.call("GET", KEYS[1])
  if not v then return nil end
  redis.call("DEL", KEYS[1])
  return v
`;

function createAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}

function createRefreshToken(userId: string, jti: string) {
  return jwt.sign({ sub: userId, jti }, REFRESH_SECRET, { expiresIn: `${REFRESH_EXPIRES_SECONDS}s` });
}

async function storeRefreshToken(jti: string, payload: any) {
  await redis.set(rtjKey(jti), JSON.stringify(payload), "EX", REFRESH_EXPIRES_SECONDS);
  await redis.sadd(userSessionsKey(payload.userId), jti);
  await redis.sadd(userDeviceKey(payload.userId, payload.deviceId), jti);
}

async function removeRefreshJti(jti: string, userId?: string, deviceId?: string) {
  await redis.del(rtjKey(jti));
  if (userId) await redis.srem(userSessionsKey(userId), jti);
  if (userId && deviceId) await redis.srem(userDeviceKey(userId, deviceId), jti);
}

async function revokeAllUserSessions(userId: string) {
  const key = userSessionsKey(userId);
  const jtis = await redis.smembers(key);
  if (jtis.length) {
    const p = redis.pipeline();
    jtis.forEach((j) => p.del(rtjKey(j)));
    p.del(key);
    await p.exec();
  }
}

async function revokeDeviceSessions(userId: string, deviceId: string) {
  const key = userDeviceKey(userId, deviceId);
  const jtis = await redis.smembers(key);
  if (jtis.length) {
    const p = redis.pipeline();
    jtis.forEach((j) => p.del(rtjKey(j)));
    p.del(key);
    await p.exec();
  }
}

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
  fingerprint: z.string().min(16),
  deviceId: z.string().min(6),
  csrf: z.string().min(8),
});

const refreshSchema = z.object({
  fingerprint: z.string().min(16),
  deviceId: z.string().min(6),
  csrf: z.string().min(8),
});

function requireCSRF(req: express.Request, res: express.Response, next: express.NextFunction) {
  const headerToken = req.headers["x-csrf-token"] as string | undefined;
  const bodyToken = req.body?.csrf as string | undefined;
  if (!headerToken || !bodyToken || headerToken !== bodyToken) {
    return res.status(403).json({ error: "CSRF check failed" });
  }

  next();
}

async function authenticateUser(username: string, password: string) {
  return `user:${username}`;
}

function normalizeIp(ip: string | undefined): string {
  if (!ip) return "";
  if (ip.startsWith("::ffff:")) return ip.replace("::ffff:", "");
  return ip;
}

function ipMatches(storedIpRaw: string | undefined, currentIpRaw: string | undefined): boolean {
  const storedIp = normalizeIp(storedIpRaw);
  const currentIp = normalizeIp(currentIpRaw);
  if (!storedIp || !currentIp) return false;

  const sParts = storedIp.split(".");
  const cParts = currentIp.split(".");
  if (sParts.length === 4 && cParts.length === 4) {
    return sParts[0] === cParts[0] && sParts[1] === cParts[1] && sParts[2] === cParts[2];
  }

  return storedIp === currentIp;
}

function userAgentMatches(storedUa: string | undefined, currentUa: string | undefined) {
  if (!storedUa || !currentUa) return false;
  return storedUa === currentUa;
}

async function incrementRefreshAttempts(userId: string, deviceId: string, windowSec = 60) {
  const key = deviceAttemptKey(userId, deviceId);
  const attempts = await redis.incr(key);
  if (attempts === 1) {
    await redis.expire(key, windowSec);
  }
  return attempts;
}

app.post("/login", requireCSRF, async (req, res) => {
  const parse = loginSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid payload", details: parse.error.format() });

  const { username, password, fingerprint, deviceId } = parse.data;
  const userId = await authenticateUser(username, password);
  if (!userId) return res.status(401).json({ error: "Invalid credentials" });

  const fpHash = await bcrypt.hash(fingerprint, 10);
  const jti = uuidv4();
  const createdAt = Date.now();

  const sessionPayload = {
    userId,
    deviceId,
    fpHash,
    ip: req.ip,
    ua: req.headers["user-agent"] || "",
    createdAt,
    lastSeenAt: createdAt,
    status: "active",
  };

  await storeRefreshToken(jti, sessionPayload);
  const refreshJwt = createRefreshToken(userId, jti);
  const accessToken = createAccessToken(userId);

  res.cookie(COOKIE_NAME, refreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_EXPIRES_SECONDS * 1000,
    path: "/",
  });

  res.json({ accessToken, deviceId });
});

app.post("/token", requireCSRF, async (req, res) => {
  const parse = refreshSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: "Invalid payload" });

  const { fingerprint, deviceId } = parse.data;
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: "No refresh token" });

  let payload: any;
  try {
    payload = jwt.verify(token, REFRESH_SECRET) as any;
  } catch (e) {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }

  const jti = payload.jti;
  if (!jti) return res.status(403).json({ error: "Malformed refresh token" });

  try {
    const attempts = await incrementRefreshAttempts(payload.sub || "unknown", deviceId, 60);
    const MAX_PER_MIN = Number(process.env.REFRESH_MAX_PER_MIN || 20);
    if (attempts > MAX_PER_MIN) {
      if (payload.sub) {
        await revokeDeviceSessions(payload.sub, deviceId);
      }
      return res.status(429).json({ error: "Too many refresh attempts. Device temporarily blocked." });
    }
  } catch (err) {
    console.warn("Failed to increment refresh attempts", err);
  }

  const blob = await redis.eval(GETDEL_LUA, 1, rtjKey(jti));
  if (!blob) {
    const suspectUser = payload.sub;
    if (suspectUser) {
      await revokeAllUserSessions(suspectUser);
    }
    return res.status(403).json({ error: "Refresh token invalid/reused. Please login again." });
  }

  const sess = JSON.parse(String(blob));
  const { userId, fpHash, status, lastSeenAt, deviceId: storedDeviceId, ip: storedIp, ua: storedUa } = sess;

  const idleSec = Math.floor((Date.now() - (lastSeenAt || sess.createdAt)) / 1000);
  const REFRESH_IDLE_TTL_SEC = Number(process.env.REFRESH_IDLE_TTL_SEC || 24 * 3600); // default 24h
  if (idleSec > REFRESH_IDLE_TTL_SEC) {
    await revokeDeviceSessions(userId, storedDeviceId);
    return res.status(403).json({ error: "Session idle expired. Login again." });
  }

  if (storedDeviceId !== deviceId) {
    await revokeDeviceSessions(userId, storedDeviceId);
    return res.status(403).json({ error: "Device mismatch. Session revoked." });
  }

  const currentIp = req.ip;
  const currentUa = req.headers["user-agent"] || "";
  const ipOk = ipMatches(storedIp, currentIp);
  const uaOk = userAgentMatches(storedUa, String(currentUa));

  if (!ipOk || !uaOk) {
    await revokeDeviceSessions(userId, storedDeviceId);
    return res.status(403).json({ error: "Device fingerprint (IP/UA) mismatch. Session revoked." });
  }

  const ok = await bcrypt.compare(fingerprint, fpHash);
  if (!ok || status !== "active") {
    await revokeDeviceSessions(userId, storedDeviceId);
    return res.status(403).json({ error: "Fingerprint mismatch or invalid session. Revoked." });
  }

  const newJti = uuidv4();
  const newSess = { ...sess, lastSeenAt: Date.now() };
  await storeRefreshToken(newJti, newSess);

  const newRefreshJwt = createRefreshToken(userId, newJti);
  res.cookie(COOKIE_NAME, newRefreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_EXPIRES_SECONDS * 1000,
    path: "/",
  });

  const newAccess = createAccessToken(userId);
  res.json({ accessToken: newAccess });
});


app.post("/logout", requireCSRF, async (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token) {
    try {
      const payload: any = jwt.verify(token, REFRESH_SECRET);
      const jti = payload.jti;
      if (jti) {
        const blob = await redis.get(rtjKey(jti));
        if (blob) {
          const sess = JSON.parse(blob);
          await removeRefreshJti(jti, sess.userId, sess.deviceId);
        } else {
          await redis.del(rtjKey(jti));
        }
      }
    } catch {
    }
  }
  
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.sendStatus(204);
});


function requireAccess(req: any, res: any, next: any) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, ACCESS_SECRET) as any;
    (req as any).user = payload;
    next();
  } catch {
    return res.sendStatus(401);
  }
}

app.get("/profile", requireAccess, (req, res) => {
  const user = (req as any).user;
  res.json({ ok: true, user });
});

app.post("/revokeAll", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });
  await revokeAllUserSessions(userId);
  return res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Auth server listening on :${PORT}`);
});
