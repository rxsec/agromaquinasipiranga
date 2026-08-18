import { revokeRefreshToken } from "../../src/auth/repository.js";
import { handleOptions, readJsonBody, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "POST") {
    return sendJson(req, res, 405, { message: "Método não permitido." });
  }

  try {
    const { refreshToken } = await readJsonBody(req);
    if (refreshToken) {
      await revokeRefreshToken(refreshToken);
    }
    return sendJson(req, res, 200, { success: true });
  } catch (error) {
    return sendJson(req, res, 500, { message: "Erro ao sair da conta." });
  }
}
