import { findUserByEmailOrCpf, saveRefreshToken } from "../../src/auth/repository.js";
import { comparePassword, signAccessToken, signRefreshToken } from "../../src/auth/security.js";
import { ensureDefaultAdminUser } from "../../src/admin/repository.js";
import { sanitizeUser } from "../../src/auth/utils.js";
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
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  try {
    await ensureDefaultAdminUser();

    const { email, password } = await readJsonBody(req);
    if (!email || !password) {
      return sendJson(req, res, 400, { message: "Informe e-mail e senha do admin." });
    }

    const admin = await findUserByEmailOrCpf(String(email).trim().toLowerCase(), "");
    if (!admin || admin.role !== "admin") {
      return sendJson(req, res, 401, { message: "Credenciais administrativas invalidas." });
    }

    const passwordMatches = await comparePassword(password, admin.password_hash);
    if (!passwordMatches) {
      return sendJson(req, res, 401, { message: "Credenciais administrativas invalidas." });
    }

    return sendAuthPayload(req, res, admin);
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao acessar o painel admin." });
  }
}
