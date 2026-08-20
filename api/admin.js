import { createUser, deleteUserById, findUserByEmailOrCpf, saveRefreshToken, updateUser } from "../src/auth/repository.js";
import { comparePassword, signAccessToken, signRefreshToken } from "../src/auth/security.js";
import {
  createCatalogItem,
  createDriver,
  createTracking,
  createYard,
  deleteCatalogItem,
  ensureDefaultAdminUser,
  getAdminDashboardData,
  updateCatalogItem,
  updateDriver
} from "../src/admin/repository.js";
import { requireAdmin } from "./_lib/admin.js";
import { handleOptions, readJsonBody, sendJson, getQueryParam } from "./_lib/http.js";
import { onlyDigits, sanitizeUser } from "../src/auth/utils.js";
import { hashPassword } from "../src/auth/security.js";

const sendAuthPayload = async (req, res, user) => {
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  await saveRefreshToken(user.id, refreshToken);

  return sendJson(req, res, 200, {
    user: sanitizeUser(user),
    accessToken,
    refreshToken
  });
};

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  const action = getQueryParam(req, "action");

  try {
    if (action === "session") {
      if (req.method !== "POST") {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      await ensureDefaultAdminUser();
      const { email, password } = await readJsonBody(req);

      if (!email || !password) {
        return sendJson(req, res, 400, { message: "Informe e-mail e senha do admin." });
      }

      const admin = await findUserByEmailOrCpf(String(email).trim().toLowerCase(), "");
      if (!admin || admin.role !== "admin") {
        return sendJson(req, res, 401, { message: "Credenciais administrativas inválidas." });
      }

      const passwordMatches = await comparePassword(password, admin.password_hash);
      if (!passwordMatches) {
        return sendJson(req, res, 401, { message: "Credenciais administrativas inválidas." });
      }

      return sendAuthPayload(req, res, admin);
    }

    const admin = await requireAdmin(req, res);
    if (!admin) {
      return;
    }

    if (action === "dashboard") {
      if (req.method !== "GET") {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      const data = await getAdminDashboardData();
      return sendJson(req, res, 200, data);
    }

    if (action === "customers") {
      if (!["POST", "PUT", "DELETE"].includes(req.method)) {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      const { id, fullName, email, whatsapp, cpf, cep, address, number, district, complement, city, state, password } =
        await readJsonBody(req);

      if (req.method === "DELETE") {
        if (!id) {
          return sendJson(req, res, 400, { message: "ID do cliente não informado." });
        }

        const deleted = await deleteUserById(String(id).trim());
        if (!deleted) {
          return sendJson(req, res, 404, { message: "Cliente não encontrado." });
        }

        return sendJson(req, res, 200, { success: true });
      }

      if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district || (!password && req.method === "POST")) {
        return sendJson(req, res, 400, { message: "Preencha todos os campos obrigatórios do cliente." });
      }

      const normalizedEmail = String(email).trim().toLowerCase();
      const normalizedCpf = onlyDigits(cpf);
      const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

      if (req.method === "PUT") {
        if (!id) {
          return sendJson(req, res, 400, { message: "ID do cliente não informado." });
        }

        if (existingUser && existingUser.id !== String(id).trim()) {
          return sendJson(req, res, 409, { message: "Já existe um cliente com este e-mail ou CPF." });
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
          return sendJson(req, res, 404, { message: "Cliente não encontrado." });
        }

        return sendJson(req, res, 200, { user: sanitizeUser(user) });
      }

      if (existingUser) {
        return sendJson(req, res, 409, { message: "Já existe um cliente com este e-mail ou CPF." });
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

      return sendJson(req, res, 201, { user: sanitizeUser(user) });
    }

    if (action === "catalog-items") {
      if (!["POST", "PUT", "DELETE"].includes(req.method)) {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      const { id, title, slug, category, sections, price, location, yearLabel, imageUrl, galleryImages, whatsapp, badge, galleryCount, description } =
        await readJsonBody(req);

      if (req.method === "DELETE") {
        if (!id) {
          return sendJson(req, res, 400, { message: "ID do item não informado." });
        }

        const deleted = await deleteCatalogItem(String(id).trim());
        if (!deleted) {
          return sendJson(req, res, 404, { message: "Item não encontrado." });
        }

        return sendJson(req, res, 200, { success: true });
      }

      if (!title || !slug || !category) {
        return sendJson(req, res, 400, { message: "Título, slug e categoria são obrigatórios." });
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
          return sendJson(req, res, 400, { message: "ID do item não informado." });
        }

        const item = await updateCatalogItem(String(id).trim(), payload);
        if (!item) {
          return sendJson(req, res, 404, { message: "Item não encontrado." });
        }

        return sendJson(req, res, 200, { item });
      }

      const item = await createCatalogItem(payload);
      return sendJson(req, res, 201, { item });
    }

    if (action === "drivers") {
      if (!["POST", "PUT"].includes(req.method)) {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      const { id, fullName, cpf, cnh, phone, email, commercialAddress, photoUrl, status, notes } = await readJsonBody(req);

      if (!fullName) {
        return sendJson(req, res, 400, { message: "Nome do motorista é obrigatório." });
      }

      if (req.method === "PUT") {
        if (!id) {
          return sendJson(req, res, 400, { message: "ID do motorista não informado." });
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
          return sendJson(req, res, 404, { message: "Motorista não encontrado." });
        }

        return sendJson(req, res, 200, { driver });
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

      return sendJson(req, res, 201, { driver });
    }

    if (action === "yards") {
      if (req.method !== "POST") {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

      const { name, city, state, address, contactName, contactPhone, capacityInfo, notes } = await readJsonBody(req);

      if (!name) {
        return sendJson(req, res, 400, { message: "Nome do pátio é obrigatório." });
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

      return sendJson(req, res, 201, { yard });
    }

    if (action === "trackings") {
      if (req.method !== "POST") {
        return sendJson(req, res, 405, { message: "Método não permitido." });
      }

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
      } = await readJsonBody(req);

      if (!clientName || !itemName || !trackingCode) {
        return sendJson(req, res, 400, { message: "Cliente, item e código de rastreio são obrigatórios." });
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

      return sendJson(req, res, 201, { tracking });
    }

    return sendJson(req, res, 404, { message: "Rota administrativa não encontrada." });
  } catch (error) {
    console.error(error);

    if (action === "session") {
      return sendJson(req, res, 500, { message: "Erro ao acessar o painel admin." });
    }

    if (action === "dashboard") {
      return sendJson(req, res, 500, { message: "Erro ao carregar o painel admin." });
    }

    if (action === "customers") {
      return sendJson(req, res, 500, { message: "Erro ao processar cliente." });
    }

    if (action === "catalog-items") {
      return sendJson(req, res, 500, { message: "Erro ao processar item do catálogo." });
    }

    if (action === "drivers") {
      return sendJson(req, res, 500, { message: "Erro ao processar motorista." });
    }

    if (action === "yards") {
      return sendJson(req, res, 500, { message: "Erro ao cadastrar pátio." });
    }

    return sendJson(req, res, 500, { message: "Erro ao cadastrar rastreio." });
  }
}
