import { createTracking } from "../../src/admin/repository.js";
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
    const {
      clientUserId,
      clientName,
      clientEmail,
      catalogItemId,
      itemName,
      driverId,
      yardId,
      trackingCode,
      status,
      currentLocation,
      expectedDeliveryDate,
      notes
    } = await readJsonBody(req);

    if (!clientName || !itemName || !trackingCode) {
      return sendJson(req, res, 400, {
        message: "Cliente, item e codigo de rastreio sao obrigatorios."
      });
    }

    const tracking = await createTracking({
      clientUserId,
      clientName: String(clientName).trim(),
      clientEmail: clientEmail ? String(clientEmail).trim().toLowerCase() : null,
      catalogItemId,
      itemName: String(itemName).trim(),
      driverId,
      yardId,
      trackingCode: String(trackingCode).trim().toUpperCase(),
      status: status ? String(status).trim() : "em separacao",
      currentLocation: currentLocation ? String(currentLocation).trim() : null,
      expectedDeliveryDate: expectedDeliveryDate || null,
      notes: notes ? String(notes).trim() : null
    });

    return sendJson(req, res, 201, { tracking });
  } catch (error) {
    console.error(error);
    return sendJson(req, res, 500, { message: "Erro ao cadastrar rastreio." });
  }
}
