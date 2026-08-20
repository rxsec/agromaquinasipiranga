import dotenv from "dotenv";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

import {
  createUser,
  deleteUserById,
  findUserByEmailOrCpf,
  findUserById,
  revokeRefreshToken,
  revokeRefreshTokenByHash,
  saveRefreshToken,
  updateUser,
  verifyRefreshTokenHash
} from "./src/auth/repository.js";
import {
  createCatalogItem,
  createDriver,
  createTracking,
  createYard,
  deleteCatalogItem,
  ensureDefaultAdminUser,
  getCustomerTrackingDashboard,
  findPublicCatalogItemBySlug,
  findPublicTrackingByCode,
  getAdminDashboardData,
  listPublicCatalogItems,
  updateCatalogItem,
  updateDriver
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

app.use(express.json({ limit: "25mb" }));
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
      return { error: { status: 401, message: "Usuário não encontrado." } };
    }

    return { user };
  } catch (error) {
    return { error: { status: 401, message: "Token inválido." } };
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
      return res.status(400).json({ message: "Preencha todos os campos obrigatórios." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (existingUser) {
      return res.status(409).json({ message: "Já existe uma conta com este e-mail ou CPF." });
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
      return res.status(401).json({ message: "Dados de acesso inválidos." });
    }

    const passwordMatches = await comparePassword(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: "Dados de acesso inválidos." });
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
      return res.status(401).json({ message: "Credenciais administrativas inválidas." });
    }

    const passwordMatches = await comparePassword(password, admin.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: "Credenciais administrativas inválidas." });
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

app.put("/api/auth/profile", authRequired, async (req, res) => {
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
      password,
      photoUrl
    } = req.body;

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district) {
      return res.status(400).json({ message: "Preencha todos os campos obrigatórios do perfil." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (existingUser && existingUser.id !== req.user.id) {
      return res.status(409).json({ message: "Já existe uma conta com este e-mail ou CPF." });
    }

    const passwordHash = password ? await hashPassword(password) : null;
    const user = await updateUser(req.user.id, {
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
      photoUrl: photoUrl ? String(photoUrl).trim() : null,
      passwordHash
    });

    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado." });
    }

    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao atualizar perfil." });
  }
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
      return res.status(401).json({ message: "Refresh token inválido." });
    }

    const user = await findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: "Usuário não encontrado." });
    }

    await revokeRefreshTokenByHash(payload.sub, refreshToken);
    return sendAuthPayload(res, user);
  } catch (error) {
    return res.status(401).json({ message: "Refresh token inválido." });
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

app.all("/api/admin/customers", adminRequired, async (req, res) => {
  try {
    if (!["POST", "PUT", "DELETE"].includes(req.method)) {
      return res.status(405).json({ message: "Método não permitido." });
    }

    const {
      id,
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

    if (req.method === "DELETE") {
      if (!id) {
        return res.status(400).json({ message: "ID do cliente não informado." });
      }

      const deleted = await deleteUserById(String(id).trim());
      if (!deleted) {
        return res.status(404).json({ message: "Cliente não encontrado." });
      }

      return res.json({ success: true });
    }

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district || !password) {
      if (req.method === "POST") {
        return res.status(400).json({ message: "Preencha todos os campos obrigatórios do cliente." });
      }
    }

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district) {
      return res.status(400).json({ message: "Preencha todos os campos obrigatórios do cliente." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (req.method === "PUT") {
      if (!id) {
        return res.status(400).json({ message: "ID do cliente não informado." });
      }

      if (!existingUser || existingUser.id !== String(id).trim()) {
        if (existingUser) {
          return res.status(409).json({ message: "Já existe um cliente com este e-mail ou CPF." });
        }
      }

      const passwordHash = password ? await hashPassword(password) : null;
      const user = await updateUser(String(id).trim(), {
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

      if (!user) {
        return res.status(404).json({ message: "Cliente não encontrado." });
      }

      return res.json({ user: sanitizeUser(user) });
    }

    if (existingUser) {
      return res.status(409).json({ message: "Já existe um cliente com este e-mail ou CPF." });
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
      passwordHash,
      role: "customer"
    });

    return res.status(201).json({ user: sanitizeUser(user) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao processar cliente." });
  }
});

app.all("/api/admin/catalog-items", adminRequired, async (req, res) => {
  try {
    if (!["POST", "PUT", "DELETE"].includes(req.method)) {
      return res.status(405).json({ message: "Método não permitido." });
    }

    const { id, title, slug, category, sections, price, location, yearLabel, imageUrl, galleryImages, whatsapp, badge, galleryCount, description } =
      req.body;

    if (req.method === "DELETE") {
      if (!id) {
        return res.status(400).json({ message: "ID do item não informado." });
      }

      const deleted = await deleteCatalogItem(String(id).trim());
      if (!deleted) {
        return res.status(404).json({ message: "Item não encontrado." });
      }

      return res.json({ success: true });
    }

    if (!title || !slug || !category) {
      return res.status(400).json({ message: "Título, slug e categoria são obrigatórios." });
    }

    const payload = {
      title: String(title).trim(),
      slug: String(slug).trim().toLowerCase(),
      category: String(category).trim(),
      sections: Array.isArray(sections) ? sections : [],
      price: Number(price || 0),
      location: location ? String(location).trim() : null,
      yearLabel: yearLabel ? String(yearLabel).trim() : null,
      imageUrl: imageUrl ? String(imageUrl).trim() : null,
      galleryImages: Array.isArray(galleryImages) ? galleryImages : [],
      whatsapp: whatsapp ? String(whatsapp).trim() : null,
      badge: badge ? String(badge).trim() : null,
      galleryCount: Number(galleryCount || 1),
      description: description ? String(description).trim() : null
    };

    if (req.method === "PUT") {
      if (!id) {
        return res.status(400).json({ message: "ID do item não informado." });
      }

      const item = await updateCatalogItem(String(id).trim(), payload);
      if (!item) {
        return res.status(404).json({ message: "Item não encontrado." });
      }

      return res.json({ item });
    }

    const item = await createCatalogItem(payload);

    return res.status(201).json({ item });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao processar item do catálogo." });
  }
});

app.all("/api/admin/drivers", adminRequired, async (req, res) => {
  try {
    if (!["POST", "PUT"].includes(req.method)) {
      return res.status(405).json({ message: "Método não permitido." });
    }

    const { id, fullName, cpf, cnh, phone, email, commercialAddress, photoUrl, status, notes } = req.body;

    if (!fullName) {
      return res.status(400).json({ message: "Nome do motorista é obrigatório." });
    }

    if (req.method === "PUT") {
      if (!id) {
        return res.status(400).json({ message: "ID do motorista não informado." });
      }

      const driver = await updateDriver(String(id).trim(), {
        fullName: String(fullName).trim(),
        cpf: cpf ? String(cpf).trim() : null,
        cnh: cnh ? String(cnh).trim() : null,
        phone: phone ? String(phone).trim() : null,
        email: email ? String(email).trim().toLowerCase() : null,
        commercialAddress: commercialAddress ? String(commercialAddress).trim() : null,
        photoUrl: photoUrl ? String(photoUrl).trim() : null,
        status: status ? String(status).trim() : "ativo",
        notes: notes ? String(notes).trim() : null
      });

      if (!driver) {
        return res.status(404).json({ message: "Motorista não encontrado." });
      }

      return res.json({ driver });
    }

    const driver = await createDriver({
      fullName: String(fullName).trim(),
      cpf: cpf ? String(cpf).trim() : null,
      cnh: cnh ? String(cnh).trim() : null,
      phone: phone ? String(phone).trim() : null,
      email: email ? String(email).trim().toLowerCase() : null,
      commercialAddress: commercialAddress ? String(commercialAddress).trim() : null,
      photoUrl: photoUrl ? String(photoUrl).trim() : null,
      status: status ? String(status).trim() : "ativo",
      notes: notes ? String(notes).trim() : null
    });

    return res.status(201).json({ driver });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao processar motorista." });
  }
});

app.post("/api/admin/yards", adminRequired, async (req, res) => {
  try {
    const { name, city, state, address, contactName, contactPhone, capacityInfo, notes } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Nome do pátio é obrigatório." });
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
    return res.status(500).json({ message: "Erro ao cadastrar pátio." });
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
      alertMessage,
      currentLocation,
      expectedDeliveryDate,
      notes
    } = req.body;

    if (!clientName || !itemName || !trackingCode) {
      return res
        .status(400)
        .json({ message: "Cliente, item e código de rastreio são obrigatórios." });
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
      status: status ? String(status).trim() : "em separação",
      alertMessage: alertMessage ? String(alertMessage).trim() : null,
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

const handleCatalogItems = async (req, res) => {
  try {
    const items = await listPublicCatalogItems({
      section: req.query.section ? String(req.query.section).trim() : null,
      category: req.query.category ? String(req.query.category).trim() : null,
      search: req.query.search ? String(req.query.search).trim() : null,
      excludeSlug: req.query.excludeSlug ? String(req.query.excludeSlug).trim() : null,
      limit: req.query.limit ? Number(req.query.limit) : null
    });

    return res.json({ items });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao carregar itens do catálogo." });
  }
};

const handleCatalogDetail = async (req, res) => {
  try {
    const slug = req.query.slug ? String(req.query.slug).trim() : "";

    if (!slug) {
      return res.status(400).json({ message: "Slug do item não informado." });
    }

    const item = await findPublicCatalogItemBySlug(slug);
    if (!item) {
      return res.status(404).json({ message: "Item não encontrado." });
    }

    return res.json({ item });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao carregar detalhe do item." });
  }
};

const handleTrackingLookup = async (req, res) => {
  try {
    const trackingCode = req.query.code ? String(req.query.code).trim().toUpperCase() : "";

    if (!trackingCode) {
      return res.status(400).json({ message: "Código de rastreio não informado." });
    }

    const tracking = await findPublicTrackingByCode(trackingCode);
    if (!tracking) {
      return res.status(404).json({ message: "Rastreio não encontrado." });
    }

    return res.json({ tracking });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao consultar rastreio." });
  }
};

app.get("/api/catalog/items", handleCatalogItems);
app.get("/api/catalog/detail", handleCatalogDetail);
app.get("/api/tracking", handleTrackingLookup);
app.get("/api/customer/tracking-dashboard", authRequired, async (req, res) => {
  try {
    const trackings = await getCustomerTrackingDashboard({
      userId: req.user.id,
      email: req.user.email
    });

    return res.json({
      user: sanitizeUser(req.user),
      trackings
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao carregar dashboard de rastreio." });
  }
});
app.get("/catalog-api-items", handleCatalogItems);
app.get("/catalog-api-detail", handleCatalogDetail);

[
  ["/admin", "admin.html"],
  ["/catalogo", "catalogo.html"],
  ["/sobre", "sobre.html"],
  ["/login", "login.html"],
  ["/cadastro", "cadastro.html"],
  ["/rastreio", "rastreio.html"],
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
