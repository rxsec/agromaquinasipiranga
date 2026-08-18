import { createCatalogItem } from "../../src/admin/repository.js";
import { requireAdmin } from "../_lib/admin.js";
import { handleOptions, readJsonBody, sendJson } from "../_lib/http.js";

export default async function handler(req, res) {
  if (handleOptions(req, res)) {
    return;
  }

  if (req.method !== "POST") {
    return sendJson(req, res, 405, { message: "Metodo nao permitido." });
  }

  const admin = await requireAdmin(req, res);
  if (!admin) {
    return;
  }

  try {
    const { title, slug, category, sections, price, location, yearLabel, imageUrl, whatsapp, badge, galleryCount, description } =
      await readJsonBody(req);

    if (!title || !slug || !category) {
      return sendJson(req, res, 400, { message: "Titulo, slug e categoria sao obrigatorios." });
    }

    const item = await createCatalogItem({
      title: String(title).trim(),
      slug: String(slug).trim().toLowerCase(),
      category: String(category).trim(),
      sections: Array.isArray(sections) ? sections : [],
      price: Number(price || 0),
      location: location ? String(location).trim() : null,
      yearLabel: yearLabel ? String(yearLabel).trim() : null,
      imageUrl: imageUrl ? String(imageUrl).trim() : null,
      whatsapp: whatsapp ? String(whatsapp).trim() : null,
      badge: badge ? String(badge).trim() : null,
      galleryCount: Number(galleryCount || 1),
      description: description ? String(description).trim() : null
    });

    return sendJson(req, res, 201, { item });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao cadastrar item do catalogo." });
  }
}
