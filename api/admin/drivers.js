import { createDriver } from "../../src/admin/repository.js";
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
    const { fullName, cpf, cnh, phone, email, status, notes } = await readJsonBody(req);

    if (!fullName) {
      return sendJson(req, res, 400, { message: "Nome do motorista é obrigatório." });
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

    return sendJson(req, res, 201, { driver });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao cadastrar motorista." });
  }
}
