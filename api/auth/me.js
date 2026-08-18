import { findUserById } from "../../src/auth/repository.js";
import { verifyAccessToken } from "../../src/auth/security.js";
import { sanitizeUser } from "../../src/auth/utils.js";
import { handleOptions, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "GET") {
    return sendJson(req, res, 405, { message: "Método não permitido." });
  }

  try {
    const authorization = req.headers.authorization || "";
    const [, token] = authorization.split(" ");

    if (!token) {
      return sendJson(req, res, 401, { message: "Token ausente." });
    }

    const payload = verifyAccessToken(token);
    const user = await findUserById(payload.sub);

    if (!user) {
      return sendJson(req, res, 401, { message: "Usuário não encontrado." });
    }

    return sendJson(req, res, 200, { user: sanitizeUser(user) });
  } catch (error) {
    return sendJson(req, res, 401, { message: "Token inválido." });
  }
}
