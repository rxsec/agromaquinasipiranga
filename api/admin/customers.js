import { createUser, findUserByEmailOrCpf, findUserById } from "../../src/auth/repository.js";
import { hashPassword, verifyAccessToken } from "../../src/auth/security.js";
import { getBearerToken } from "../../src/auth/request.js";
import { onlyDigits, sanitizeUser } from "../../src/auth/utils.js";

const parseBody = (req) => {
  if (!req.body) {
    return {};
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch (_error) {
      return {};
    }
  }

  return req.body;
};

const resolveAdminUser = async (req) => {
  const token = getBearerToken(req.headers.authorization);

  if (!token) {
    return { error: { status: 401, message: "Token ausente." } };
  }

  try {
    const payload = verifyAccessToken(token);
    const user = await findUserById(payload.sub);

    if (!user) {
      return { error: { status: 401, message: "Usuário não encontrado." } };
    }

    if (user.role !== "admin") {
      return { error: { status: 403, message: "Acesso restrito ao administrador." } };
    }

    return { user };
  } catch (_error) {
    return { error: { status: 401, message: "Token inválido." } };
  }
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "Método não permitido." });
  }

  const { error } = await resolveAdminUser(req);
  if (error) {
    return res.status(error.status).json({ message: error.message });
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
    } = parseBody(req);

    if (!fullName || !email || !whatsapp || !cpf || !cep || !address || !number || !district || !password) {
      return res.status(400).json({ message: "Preencha todos os campos obrigatórios do cliente." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedCpf = onlyDigits(cpf);
    const existingUser = await findUserByEmailOrCpf(normalizedEmail, normalizedCpf);

    if (existingUser) {
      return res.status(409).json({ message: "Já existe um cliente com este e-mail ou CPF." });
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
      passwordHash,
      role: "customer"
    });

    return res.status(201).json({ user: sanitizeUser(user) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Erro ao cadastrar cliente." });
  }
}
