import crypto from "crypto";

import { pool } from "./db.js";

const hashRefreshToken = (refreshToken) =>
  crypto.createHash("sha256").update(refreshToken).digest("hex");

export const createUser = async ({
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
  passwordHash
}) => {
  const query = `
    insert into public.app_users (
      full_name,
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
      password_hash
    )
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    returning id, full_name, email, whatsapp, cpf, cep, address, number, district, complement, city, state, created_at
  `;

  const { rows } = await pool.query(query, [
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
    passwordHash
  ]);

  return rows[0];
};

export const findUserByEmailOrCpf = async (email, cpfDigits) => {
  const query = `
    select
      id,
      full_name,
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
      password_hash,
      created_at
    from public.app_users
    where lower(email) = lower($1)
       or regexp_replace(cpf, '\\D', '', 'g') = $2
    limit 1
  `;

  const { rows } = await pool.query(query, [email, cpfDigits]);
  return rows[0] || null;
};

export const findUserById = async (id) => {
  const query = `
    select
      id,
      full_name,
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
      password_hash,
      created_at
    from public.app_users
    where id = $1
    limit 1
  `;

  const { rows } = await pool.query(query, [id]);
  return rows[0] || null;
};

export const saveRefreshToken = async (userId, refreshToken) => {
  const tokenHash = hashRefreshToken(refreshToken);
  await pool.query(
    `
      insert into public.app_refresh_tokens (user_id, token_hash, expires_at)
      values ($1, $2, now() + interval '30 days')
    `,
    [userId, tokenHash]
  );
};

export const verifyRefreshTokenHash = async (userId, refreshToken) => {
  const tokenHash = hashRefreshToken(refreshToken);
  const { rows } = await pool.query(
    `
      select id
      from public.app_refresh_tokens
      where user_id = $1
        and token_hash = $2
        and revoked_at is null
        and expires_at > now()
      limit 1
    `,
    [userId, tokenHash]
  );
  return rows[0] || null;
};

export const revokeRefreshTokenByHash = async (userId, refreshToken) => {
  const tokenHash = hashRefreshToken(refreshToken);
  await pool.query(
    `
      update public.app_refresh_tokens
      set revoked_at = now()
      where user_id = $1 and token_hash = $2 and revoked_at is null
    `,
    [userId, tokenHash]
  );
};

export const revokeRefreshToken = async (refreshToken) => {
  const tokenHash = hashRefreshToken(refreshToken);
  await pool.query(
    `
      update public.app_refresh_tokens
      set revoked_at = now()
      where token_hash = $1 and revoked_at is null
    `,
    [tokenHash]
  );
};
