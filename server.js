import dotenv from "dotenv";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

import {
  createUser,
  findUserByEmailOrCpf,
  findUserById,
  revokeRefreshToken,
  revokeRefreshTokenByHash,
  saveRefreshToken,
  verifyRefreshTokenHash
} from "./src/auth/repository.js";
import {
  comparePassword,
  hashPassword,
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken
} from "./src/auth/security.js";
import { onlyDigits, sanitizeUser } from "./src/auth/utils.js";

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const port = Number(process.env.PORT || 3000);
const appUrl = process.env.APP_URL || `http://localhost:${port}`;
const appDomain = process.env.APP_DOMAIN || "localhost";
const allowedOrigins = (process.env.CORS_ORIGIN || appUrl)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(express.json());
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  return next();
});
app.use(express.static(__dirname));

const sendAuthPayload = async (res, user) => {
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  await saveRefreshToken(user.id, refreshToken);

  res.json({
    user: sanitizeUser(user),
    accessToken,
    refreshToken
  });
};

const authRequired = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization || "";
    const [, token] = authorization.split(" ");

    if (!token) {
      return res.status(401).json({ message: "Token ausente." });
    }

    const payload = verifyAccessToken(token);
    const user = await findUserById(payload.sub);

    if (!user) {
      return res.status(401).json({ message: "Usuario nao encontrado." });
    }

    req.user = user;
    return next();
  } catch (error) {
    return res.status(401).json({ message: "Token invalido." });
  }
};

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      fullName,
      email,
      whatsapp,
      cpf,
      cep,
      address,
      number,
      district,
      complement,
      city,
      state,
      password
    } = req.body;

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district || !password) {
      return res.status(400).json({ message: "Preencha todos os campos obrigatorios." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (existingUser) {
      return res.status(409).json({ message: "Ja existe uma conta com este e-mail ou CPF." });
    }

    const passwordHash = await hashPassword(password);
    const user = await createUser({
      fullName: String(fullName).trim(),
      email: normalizedEmail,
      whatsapp: String(whatsapp).trim(),
      cpf: String(cpf).trim(),
      cep: String(cep).trim(),
      address: String(address).trim(),
      number: String(number).trim(),
      district: String(district).trim(),
      complement: complement ? String(complement).trim() : null,
      city: city ? String(city).trim() : null,
      state: state ? String(state).trim() : null,
      passwordHash
    });

    return sendAuthPayload(res, user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao criar conta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ message: "Informe e-mail/CPF e senha." });
    }

    const normalizedIdentifier = String(identifier).trim().toLowerCase();
    const user = await findUserByEmailOrCpf(normalizedIdentifier, onlyDigits(normalizedIdentifier));

    if (!user) {
      return res.status(401).json({ message: "Dados de acesso invalidos." });
    }

    const passwordMatches = await comparePassword(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: "Dados de acesso invalidos." });
    }

    return sendAuthPayload(res, user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao fazer login." });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  return res.json({ user: sanitizeUser(req.user) });
});

app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token ausente." });
    }

    const payload = verifyRefreshToken(refreshToken);
    const tokenExists = await verifyRefreshTokenHash(payload.sub, refreshToken);

    if (!tokenExists) {
      return res.status(401).json({ message: "Refresh token invalido." });
    }

    const user = await findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: "Usuario nao encontrado." });
    }

    await revokeRefreshTokenByHash(payload.sub, refreshToken);
    return sendAuthPayload(res, user);
  } catch (error) {
    return res.status(401).json({ message: "Refresh token invalido." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      await revokeRefreshToken(refreshToken);
    }
    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ message: "Erro ao sair da conta." });
  }
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(port, () => {
  console.log(`Servidor rodando em ${appUrl}`);
  console.log(`Dominio configurado: ${appDomain}`);
  console.log(`CORS liberado para: ${allowedOrigins.join(", ")}`);
});
