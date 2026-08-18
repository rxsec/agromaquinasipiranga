import { findPublicCatalogItemBySlug } from "../../src/admin/repository.js";
import { handleOptions, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "GET") {
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  try {
    const slug = req.query.slug ? String(req.query.slug).trim() : "";

    if (!slug) {
      return sendJson(req, res, 400, { message: "Slug do item nao informado." });
    }

    const item = await findPublicCatalogItemBySlug(slug);
    if (!item) {
      return sendJson(req, res, 404, { message: "Item nao encontrado." });
    }

    return sendJson(req, res, 200, { item });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao carregar detalhe do item." });
  }
}
