import { verifyAccessToken } from "../../src/auth/security.js";
import { findUserById } from "../../src/auth/repository.js";
import { getBearerToken } from "../../src/auth/request.js";
import { sendJson } from "./http.js";

export const requireAdmin = async (req, res) => {
  try {
    const token = getBearerToken(req.headers.authorization);

    if (!token) {
      sendJson(req, res, 401, { message: "Token ausente." });
      return null;
    }

    const payload = verifyAccessToken(token);
    const user = await findUserById(payload.sub);

    if (!user) {
      sendJson(req, res, 401, { message: "Usuário não encontrado." });
      return null;
    }

    if (user.role !== "admin") {
      sendJson(req, res, 403, { message: "Acesso restrito ao administrador." });
      return null;
    }

    return user;
  } catch (error) {
    sendJson(req, res, 401, { message: "Token inválido." });
    return null;
  }
};
