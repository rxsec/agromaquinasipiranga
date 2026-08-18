import { createYard } from "../../src/admin/repository.js";
import { requireAdmin } from "../_lib/admin.js";
import { handleOptions, readJsonBody, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "POST") {
    return sendJson(req, res, 405, { message: "Método não permitido." });
  }

  const admin = await requireAdmin(req, res);
  if (!admin) {
    return;
  }

  try {
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
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao cadastrar pátio." });
  }
}
