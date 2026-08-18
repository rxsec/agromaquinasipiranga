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
  createCatalogItem,
  createDriver,
  createTracking,
  createYard,
  ensureDefaultAdminUser,
  getAdminDashboardData
} from "./src/admin/repository.js";
import {
  comparePassword,
  hashPassword,
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken
} from "./src/auth/security.js";
import { getBearerToken } from "./src/auth/request.js";
import { onlyDigits, sanitizeUser } from "./src/auth/utils.js";

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");
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
app.use(express.static(publicDir));

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

const resolveRequestUser = async (req) => {
  const token = getBearerToken(req.headers.authorization);

  if (!token) {
    return { error: { status: 401, message: "Token ausente." } };
  }

  try {
    const payload = verifyAccessToken(token);
    const user = await findUserById(payload.sub);

    if (!user) {
      return { error: { status: 401, message: "Usuario nao encontrado." } };
    }

    return { user };
  } catch (error) {
    return { error: { status: 401, message: "Token invalido." } };
  }
};

const authRequired = async (req, res, next) => {
  const { user, error } = await resolveRequestUser(req);

  if (error) {
    return res.status(error.status).json({ message: error.message });
  }

  req.user = user;
  return next();
};

const adminRequired = async (req, res, next) => {
  const { user, error } = await resolveRequestUser(req);

  if (error) {
    return res.status(error.status).json({ message: error.message });
  }

  if (user.role !== "admin") {
    return res.status(403).json({ message: "Acesso restrito ao administrador." });
  }

  req.user = user;
  return next();
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

app.post("/api/admin/session", async (req, res) => {
  try {
    await ensureDefaultAdminUser();

    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Informe e-mail e senha do admin." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const admin = await findUserByEmailOrCpf(normalizedEmail, "");

    if (!admin || admin.role !== "admin") {
      return res.status(401).json({ message: "Credenciais administrativas invalidas." });
    }

    const passwordMatches = await comparePassword(password, admin.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: "Credenciais administrativas invalidas." });
    }

    return sendAuthPayload(res, admin);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao acessar o painel admin." });
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

app.get("/api/admin/dashboard", adminRequired, async (_req, res) => {
  try {
    const data = await getAdminDashboardData();
    return res.json(data);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao carregar o painel admin." });
  }
});

app.post("/api/admin/catalog-items", adminRequired, async (req, res) => {
  try {
    const { title, slug, category, sections, price, location, yearLabel, imageUrl, whatsapp, badge, galleryCount, description } =
      req.body;

    if (!title || !slug || !category) {
      return res.status(400).json({ message: "Titulo, slug e categoria sao obrigatorios." });
    }

    const item = await createCatalogItem({
      title: String(title).trim(),
      slug: String(slug).trim().toLowerCase(),
      category: String(category).trim(),
      sections: Array.isArray(sections) ? sections : [],
      price: Number(price || 0),
      location: location ? String(location).trim() : null,
      yearLabel: yearLabel ? String(yearLabel).trim() : null,
      imageUrl: imageUrl ? String(imageUrl).trim() : null,
      whatsapp: whatsapp ? String(whatsapp).trim() : null,
      badge: badge ? String(badge).trim() : null,
      galleryCount: Number(galleryCount || 1),
      description: description ? String(description).trim() : null
    });

    return res.status(201).json({ item });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao cadastrar item do catalogo." });
  }
});

app.post("/api/admin/drivers", adminRequired, async (req, res) => {
  try {
    const { fullName, cpf, cnh, phone, email, status, notes } = req.body;

    if (!fullName) {
      return res.status(400).json({ message: "Nome do motorista e obrigatorio." });
    }

    const driver = await createDriver({
      fullName: String(fullName).trim(),
      cpf: cpf ? String(cpf).trim() : null,
      cnh: cnh ? String(cnh).trim() : null,
      phone: phone ? String(phone).trim() : null,
      email: email ? String(email).trim().toLowerCase() : null,
      status: status ? String(status).trim() : "ativo",
      notes: notes ? String(notes).trim() : null
    });

    return res.status(201).json({ driver });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao cadastrar motorista." });
  }
});

app.post("/api/admin/yards", adminRequired, async (req, res) => {
  try {
    const { name, city, state, address, contactName, contactPhone, capacityInfo, notes } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Nome do patio e obrigatorio." });
    }

    const yard = await createYard({
      name: String(name).trim(),
      city: city ? String(city).trim() : null,
      state: state ? String(state).trim() : null,
      address: address ? String(address).trim() : null,
      contactName: contactName ? String(contactName).trim() : null,
      contactPhone: contactPhone ? String(contactPhone).trim() : null,
      capacityInfo: capacityInfo ? String(capacityInfo).trim() : null,
      notes: notes ? String(notes).trim() : null
    });

    return res.status(201).json({ yard });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao cadastrar patio." });
  }
});

app.post("/api/admin/trackings", adminRequired, async (req, res) => {
  try {
    const {
      clientUserId,
      clientName,
      clientEmail,
      catalogItemId,
      itemName,
      driverId,
      yardId,
      trackingCode,
      status,
      currentLocation,
      expectedDeliveryDate,
      notes
    } = req.body;

    if (!clientName || !itemName || !trackingCode) {
      return res
        .status(400)
        .json({ message: "Cliente, item e codigo de rastreio sao obrigatorios." });
    }

    const tracking = await createTracking({
      clientUserId,
      clientName: String(clientName).trim(),
      clientEmail: clientEmail ? String(clientEmail).trim().toLowerCase() : null,
      catalogItemId,
      itemName: String(itemName).trim(),
      driverId,
      yardId,
      trackingCode: String(trackingCode).trim().toUpperCase(),
      status: status ? String(status).trim() : "em separacao",
      currentLocation: currentLocation ? String(currentLocation).trim() : null,
      expectedDeliveryDate: expectedDeliveryDate || null,
      notes: notes ? String(notes).trim() : null
    });

    return res.status(201).json({ tracking });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao cadastrar rastreio." });
  }
});

[
  ["/admin", "admin.html"],
  ["/catalogo", "catalogo.html"],
  ["/sobre", "sobre.html"],
  ["/login", "login.html"],
  ["/cadastro", "cadastro.html"],
  ["/detalhe", "detalhe.html"],
  ["/", "index.html"]
].forEach(([routePath, fileName]) => {
  app.get(routePath, (_req, res) => {
    res.sendFile(path.join(publicDir, fileName));
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando em ${appUrl}`);
  console.log(`Dominio configurado: ${appDomain}`);
  console.log(`CORS liberado para: ${allowedOrigins.join(", ")}`);
});
