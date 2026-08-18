import {
  findUserById,
  revokeRefreshTokenByHash,
  saveRefreshToken,
  verifyRefreshTokenHash
} from "../../src/auth/repository.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../../src/auth/security.js";
import { sanitizeUser } from "../../src/auth/utils.js";
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

    if (!refreshToken) {
      return sendJson(req, res, 400, { message: "Refresh token ausente." });
    }

    const payload = verifyRefreshToken(refreshToken);
    const tokenExists = await verifyRefreshTokenHash(payload.sub, refreshToken);

    if (!tokenExists) {
      return sendJson(req, res, 401, { message: "Refresh token inválido." });
    }

    const user = await findUserById(payload.sub);
    if (!user) {
      return sendJson(req, res, 401, { message: "Usuário não encontrado." });
    }

    await revokeRefreshTokenByHash(payload.sub, refreshToken);

    const nextAccessToken = signAccessToken(user);
    const nextRefreshToken = signRefreshToken(user);
    await saveRefreshToken(user.id, nextRefreshToken);

    return sendJson(req, res, 200, {
      user: sanitizeUser(user),
      accessToken: nextAccessToken,
      refreshToken: nextRefreshToken
    });
  } catch (error) {
    return sendJson(req, res, 401, { message: "Refresh token inválido." });
  }
}
