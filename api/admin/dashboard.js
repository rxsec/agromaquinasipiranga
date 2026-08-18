import { getAdminDashboardData } from "../../src/admin/repository.js";
import { requireAdmin } from "../_lib/admin.js";
import { handleOptions, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "GET") {
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  const admin = await requireAdmin(req, res);
  if (!admin) {
    return;
  }

  try {
    const data = await getAdminDashboardData();
    return sendJson(req, res, 200, data);
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao carregar o painel admin." });
  }
}
