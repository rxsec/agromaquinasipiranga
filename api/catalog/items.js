import { listPublicCatalogItems } from "../../src/admin/repository.js";
import { getQueryParam, handleOptions, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "GET") {
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  try {
    const section = getQueryParam(req, "section");
    const category = getQueryParam(req, "category");
    const search = getQueryParam(req, "search");
    const excludeSlug = getQueryParam(req, "excludeSlug");
    const limit = getQueryParam(req, "limit");

    const items = await listPublicCatalogItems({
      section: section ? String(section).trim() : null,
      category: category ? String(category).trim() : null,
      search: search ? String(search).trim() : null,
      excludeSlug: excludeSlug ? String(excludeSlug).trim() : null,
      limit: limit ? Number(limit) : null
    });

    return sendJson(req, res, 200, { items });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao carregar itens do catalogo." });
  }
}
