import { createUser, findUserByEmailOrCpf, saveRefreshToken } from "../../src/auth/repository.js";
import { hashPassword, signAccessToken, signRefreshToken } from "../../src/auth/security.js";
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
    const {
      fullName,
      email,
      whatsapp,
      cpf,
      cep,
      address,
      number,
      district,
      complement,
      city,
      state,
      password
    } = await readJsonBody(req);

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district || !password) {
      return sendJson(req, res, 400, { message: "Preencha todos os campos obrigatórios." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (existingUser) {
      return sendJson(req, res, 409, { message: "Ja existe uma conta com este e-mail ou CPF." });
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
      passwordHash
    });

    return sendAuthPayload(req, res, user);
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao criar conta." });
  }
}
