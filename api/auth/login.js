import { findUserByEmailOrCpf, saveRefreshToken } from "../../src/auth/repository.js";
import { comparePassword, signAccessToken, signRefreshToken } from "../../src/auth/security.js";
import { onlyDigits, sanitizeUser } from "../../src/auth/utils.js";
import { handleOptions, readJsonBody, sendJson } from "../_lib/http.js";

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

  if (req.method !== "POST") {
    return sendJson(req, res, 405, { message: "Método não permitido." });
  }

  try {
    const { identifier, password } = await readJsonBody(req);

    if (!identifier || !password) {
      return sendJson(req, res, 400, { message: "Informe e-mail/CPF e senha." });
    }

    const normalizedIdentifier = String(identifier).trim().toLowerCase();
    const user = await findUserByEmailOrCpf(normalizedIdentifier, onlyDigits(normalizedIdentifier));

    if (!user) {
      return sendJson(req, res, 401, { message: "Dados de acesso inválidos." });
    }

    const passwordMatches = await comparePassword(password, user.password_hash);
    if (!passwordMatches) {
      return sendJson(req, res, 401, { message: "Dados de acesso inválidos." });
    }

    return sendAuthPayload(req, res, user);
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao fazer login." });
  }
}
