import { createCatalogItem, deleteCatalogItem, updateCatalogItem } from "../../src/admin/repository.js";
import { requireAdmin } from "../_lib/admin.js";
import { handleOptions, readJsonBody, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (!["POST", "PUT", "DELETE"].includes(req.method)) {
    return sendJson(req, res, 405, { message: "Método não permitido." });
  }

  const admin = await requireAdmin(req, res);
  if (!admin) {
    return;
  }

  try {
    const { id, title, slug, category, sections, price, location, yearLabel, imageUrl, galleryImages, whatsapp, badge, galleryCount, description } =
      await readJsonBody(req);

    if (req.method === "DELETE") {
      if (!id) {
        return sendJson(req, res, 400, { message: "ID do item não informado." });
      }

      const deleted = await deleteCatalogItem(String(id).trim());
      if (!deleted) {
        return sendJson(req, res, 404, { message: "Item não encontrado." });
      }

      return sendJson(req, res, 200, { success: true });
    }

    if (!title || !slug || !category) {
      return sendJson(req, res, 400, {
        message: "Título, slug e categoria são obrigatórios."
      });
    }

    const payload = {
      title: String(title).trim(),
      slug: String(slug).trim().toLowerCase(),
      category: String(category).trim(),
      sections: Array.isArray(sections) ? sections : [],
      price: Number(price || 0),
      location: location ? String(location).trim() : null,
      yearLabel: yearLabel ? String(yearLabel).trim() : null,
      imageUrl: imageUrl ? String(imageUrl).trim() : null,
      galleryImages: Array.isArray(galleryImages) ? galleryImages : [],
      whatsapp: whatsapp ? String(whatsapp).trim() : null,
      badge: badge ? String(badge).trim() : null,
      galleryCount: Number(galleryCount || 1),
      description: description ? String(description).trim() : null
    };

    if (req.method === "PUT") {
      if (!id) {
        return sendJson(req, res, 400, { message: "ID do item não informado." });
      }

      const item = await updateCatalogItem(String(id).trim(), payload);
      if (!item) {
        return sendJson(req, res, 404, { message: "Item não encontrado." });
      }

      return sendJson(req, res, 200, { item });
    }

    const item = await createCatalogItem(payload);

    return sendJson(req, res, 201, { item });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao processar item do catálogo." });
  }
}
