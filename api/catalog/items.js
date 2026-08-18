import { listPublicCatalogItems } from "../../src/admin/repository.js";
import { handleOptions, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "GET") {
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  try {
    const items = await listPublicCatalogItems({
      section: req.query.section ? String(req.query.section).trim() : null,
      category: req.query.category ? String(req.query.category).trim() : null,
      search: req.query.search ? String(req.query.search).trim() : null,
      excludeSlug: req.query.excludeSlug ? String(req.query.excludeSlug).trim() : null,
      limit: req.query.limit ? Number(req.query.limit) : null
    });

    return sendJson(req, res, 200, { items });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao carregar itens do catalogo." });
  }
}
