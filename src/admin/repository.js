import { pool } from "../auth/db.js";
import { comparePassword, hashPassword } from "../auth/security.js";
import { createUser, findUserByEmailOrCpf, updateUserPasswordAndRole } from "../auth/repository.js";
import { DEFAULT_CATALOG_ITEMS } from "./default-catalog.js";

const DEFAULT_ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@agromaquinasipiranga.com.br";
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "agro@2026";

let adminSchemaPromise;
let defaultCatalogPromise;

export const ensureAdminSchema = async () => {
  if (!adminSchemaPromise) {
    adminSchemaPromise = pool.query(`
      alter table public.app_users
      add column if not exists role text not null default 'customer';

      create index if not exists app_users_role_idx on public.app_users (role);

      create table if not exists public.app_catalog_items (
        id uuid primary key default gen_random_uuid(),
        title text not null,
        slug text not null unique,
        category text not null,
        sections text[] not null default '{}',
        price numeric(12, 2) not null default 0,
        location text,
        year_label text,
        image_url text,
        gallery_images jsonb not null default '[]'::jsonb,
        whatsapp text,
        badge text,
        gallery_count integer not null default 1,
        description text,
        is_published boolean not null default true,
        created_at timestamptz not null default timezone('utc', now()),
        updated_at timestamptz not null default timezone('utc', now())
      );

      alter table public.app_catalog_items
      add column if not exists gallery_images jsonb not null default '[]'::jsonb;

      create table if not exists public.app_drivers (
        id uuid primary key default gen_random_uuid(),
        full_name text not null,
        cpf text,
        cnh text,
        phone text,
        email text,
        status text not null default 'ativo',
        notes text,
        created_at timestamptz not null default timezone('utc', now()),
        updated_at timestamptz not null default timezone('utc', now())
      );

      create table if not exists public.app_yards (
        id uuid primary key default gen_random_uuid(),
        name text not null,
        city text,
        state text,
        address text,
        contact_name text,
        contact_phone text,
        capacity_info text,
        notes text,
        created_at timestamptz not null default timezone('utc', now()),
        updated_at timestamptz not null default timezone('utc', now())
      );

      create table if not exists public.app_client_tracking (
        id uuid primary key default gen_random_uuid(),
        client_user_id uuid references public.app_users(id) on delete set null,
        client_name text not null,
        client_email text,
        catalog_item_id uuid references public.app_catalog_items(id) on delete set null,
        item_name text not null,
        driver_id uuid references public.app_drivers(id) on delete set null,
        yard_id uuid references public.app_yards(id) on delete set null,
        tracking_code text not null unique,
        status text not null default 'em separacao',
        current_location text,
        expected_delivery_date date,
        notes text,
        created_at timestamptz not null default timezone('utc', now()),
        updated_at timestamptz not null default timezone('utc', now())
      );

      create index if not exists app_catalog_items_category_idx on public.app_catalog_items (category);
      create index if not exists app_catalog_items_sections_idx on public.app_catalog_items using gin (sections);
      create index if not exists app_drivers_status_idx on public.app_drivers (status);
      create index if not exists app_yards_state_idx on public.app_yards (state);
      create index if not exists app_client_tracking_status_idx on public.app_client_tracking (status);
      create index if not exists app_client_tracking_client_user_id_idx on public.app_client_tracking (client_user_id);

      drop trigger if exists set_app_catalog_items_updated_at on public.app_catalog_items;
      create trigger set_app_catalog_items_updated_at
      before update on public.app_catalog_items
      for each row
      execute function public.set_updated_at();

      drop trigger if exists set_app_drivers_updated_at on public.app_drivers;
      create trigger set_app_drivers_updated_at
      before update on public.app_drivers
      for each row
      execute function public.set_updated_at();

      drop trigger if exists set_app_yards_updated_at on public.app_yards;
      create trigger set_app_yards_updated_at
      before update on public.app_yards
      for each row
      execute function public.set_updated_at();

      drop trigger if exists set_app_client_tracking_updated_at on public.app_client_tracking;
      create trigger set_app_client_tracking_updated_at
      before update on public.app_client_tracking
      for each row
      execute function public.set_updated_at();
    `);
  }

  return adminSchemaPromise;
};

export const ensureDefaultAdminUser = async () => {
  await ensureAdminSchema();

  const admin = await findUserByEmailOrCpf(DEFAULT_ADMIN_EMAIL, "");
  const passwordHash = await hashPassword(DEFAULT_ADMIN_PASSWORD);

  if (!admin) {
    return createUser({
      fullName: "Administrador Agro Máquinas Ipiranga",
      email: DEFAULT_ADMIN_EMAIL,
      whatsapp: "(43) 99999-9999",
      cpf: "000.000.000-00",
      cep: "00000-000",
      address: "Painel Administrativo",
      number: "S/N",
      district: "Centro",
      complement: null,
      city: "Ipiranga",
      state: "PR",
      passwordHash,
      role: "admin"
    });
  }

  const passwordMatches = await comparePassword(DEFAULT_ADMIN_PASSWORD, admin.password_hash);
  if (admin.role !== "admin" || !passwordMatches) {
    return updateUserPasswordAndRole(admin.id, passwordHash, "admin");
  }

  return admin;
};

export const ensureDefaultCatalogItems = async () => {
  await ensureAdminSchema();

  if (!defaultCatalogPromise) {
    defaultCatalogPromise = (async () => {
      for (const item of DEFAULT_CATALOG_ITEMS) {
        await pool.query(
          `
            insert into public.app_catalog_items (
              title, slug, category, sections, price, location, year_label, image_url, gallery_images,
              whatsapp, badge, gallery_count, description, is_published
            )
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,true)
            on conflict (slug) do nothing
          `,
          [
            item.title,
            item.slug,
            item.category,
            item.sections,
            item.price,
            item.location,
            item.yearLabel,
            item.imageUrl,
            JSON.stringify([item.imageUrl]),
            item.whatsapp || "5512997371569",
            item.badge || item.category,
            1,
            item.description
          ]
        );
      }
    })();
  }

  return defaultCatalogPromise;
};

export const getAdminDashboardData = async () => {
  await ensureAdminSchema();
  await ensureDefaultCatalogItems();

  const [users, catalogItems, drivers, yards, trackings] = await Promise.all([
    pool.query(`
      select id, full_name, email, whatsapp, cpf, city, state, role, created_at
      from public.app_users
      order by created_at desc
    `),
    pool.query(`
      select id, title, slug, category, sections, price, location, year_label, image_url, gallery_images, badge, gallery_count, is_published, created_at
      from public.app_catalog_items
      order by created_at desc
    `),
    pool.query(`
      select id, full_name, cpf, cnh, phone, email, status, notes, created_at
      from public.app_drivers
      order by created_at desc
    `),
    pool.query(`
      select id, name, city, state, address, contact_name, contact_phone, capacity_info, notes, created_at
      from public.app_yards
      order by created_at desc
    `),
    pool.query(`
      select
        t.id,
        t.client_name,
        t.client_email,
        t.item_name,
        t.tracking_code,
        t.status,
        t.current_location,
        t.expected_delivery_date,
        t.notes,
        t.created_at,
        d.full_name as driver_name,
        y.name as yard_name
      from public.app_client_tracking t
      left join public.app_drivers d on d.id = t.driver_id
      left join public.app_yards y on y.id = t.yard_id
      order by t.created_at desc
    `)
  ]);

  return {
    users: users.rows,
    catalogItems: catalogItems.rows,
    drivers: drivers.rows,
    yards: yards.rows,
    trackings: trackings.rows
  };
};

export const createCatalogItem = async ({
  title,
  slug,
  category,
  sections,
  price,
  location,
  yearLabel,
  imageUrl,
  galleryImages,
  whatsapp,
  badge,
  galleryCount,
  description
}) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      insert into public.app_catalog_items (
        title, slug, category, sections, price, location, year_label, image_url, gallery_images, whatsapp, badge, gallery_count, description
      )
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13)
      returning *
    `,
    [
      title,
      slug,
      category,
      sections,
      price,
      location,
      yearLabel,
      imageUrl,
      JSON.stringify(Array.isArray(galleryImages) ? galleryImages : []),
      whatsapp,
      badge,
      galleryCount,
      description
    ]
  );

  return rows[0];
};

export const updateCatalogItem = async (
  id,
  {
    title,
    slug,
    category,
    sections,
    price,
    location,
    yearLabel,
    imageUrl,
    galleryImages,
    whatsapp,
    badge,
    galleryCount,
    description
  }
) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      update public.app_catalog_items
      set
        title = $2,
        slug = $3,
        category = $4,
        sections = $5,
        price = $6,
        location = $7,
        year_label = $8,
        image_url = $9,
        gallery_images = $10::jsonb,
        whatsapp = $11,
        badge = $12,
        gallery_count = $13,
        description = $14,
        updated_at = timezone('utc', now())
      where id = $1
      returning *
    `,
    [
      id,
      title,
      slug,
      category,
      sections,
      price,
      location,
      yearLabel,
      imageUrl,
      JSON.stringify(Array.isArray(galleryImages) ? galleryImages : []),
      whatsapp,
      badge,
      galleryCount,
      description
    ]
  );

  return rows[0] || null;
};

export const deleteCatalogItem = async (id) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      delete from public.app_catalog_items
      where id = $1
      returning id
    `,
    [id]
  );

  return rows[0] || null;
};

export const createDriver = async ({ fullName, cpf, cnh, phone, email, status, notes }) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      insert into public.app_drivers (full_name, cpf, cnh, phone, email, status, notes)
      values ($1,$2,$3,$4,$5,$6,$7)
      returning *
    `,
    [fullName, cpf, cnh, phone, email, status, notes]
  );

  return rows[0];
};

export const createYard = async ({
  name,
  city,
  state,
  address,
  contactName,
  contactPhone,
  capacityInfo,
  notes
}) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      insert into public.app_yards (name, city, state, address, contact_name, contact_phone, capacity_info, notes)
      values ($1,$2,$3,$4,$5,$6,$7,$8)
      returning *
    `,
    [name, city, state, address, contactName, contactPhone, capacityInfo, notes]
  );

  return rows[0];
};

export const createTracking = async ({
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
}) => {
  await ensureAdminSchema();

  const { rows } = await pool.query(
    `
      insert into public.app_client_tracking (
        client_user_id, client_name, client_email, catalog_item_id, item_name, driver_id, yard_id,
        tracking_code, status, current_location, expected_delivery_date, notes
      )
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      returning *
    `,
    [
      clientUserId || null,
      clientName,
      clientEmail,
      catalogItemId || null,
      itemName,
      driverId || null,
      yardId || null,
      trackingCode,
      status,
      currentLocation,
      expectedDeliveryDate || null,
      notes
    ]
  );

  return rows[0];
};

export const listPublicCatalogItems = async ({
  section = null,
  category = null,
  search = null,
  excludeSlug = null,
  limit = null
} = {}) => {
  await ensureAdminSchema();
  await ensureDefaultCatalogItems();

  const conditions = ["is_published = true"];
  const values = [];

  if (section) {
    values.push(section);
    conditions.push(`$${values.length} = any(sections)`);
  }

  if (category) {
    values.push(category);
    conditions.push(`category ilike $${values.length}`);
  }

  if (search) {
    values.push(`%${search}%`);
    conditions.push(`(title ilike $${values.length} or category ilike $${values.length} or coalesce(location, '') ilike $${values.length})`);
  }

  if (excludeSlug) {
    values.push(excludeSlug);
    conditions.push(`slug <> $${values.length}`);
  }

  const limitClause = limit ? `limit ${Number(limit)}` : "";
  const query = `
    select
      id,
      title,
      slug,
      category,
      sections,
      price,
      location,
      year_label,
      image_url,
      gallery_images,
      whatsapp,
      badge,
      gallery_count,
      description,
      is_published,
      created_at
    from public.app_catalog_items
    where ${conditions.join(" and ")}
    order by created_at desc
    ${limitClause}
  `;

  const { rows } = await pool.query(query, values);
  return rows;
};

export const findPublicCatalogItemBySlug = async (slug) => {
  await ensureAdminSchema();
  await ensureDefaultCatalogItems();

  const { rows } = await pool.query(
    `
      select
        id,
        title,
        slug,
        category,
        sections,
        price,
        location,
        year_label,
        image_url,
        gallery_images,
        whatsapp,
        badge,
        gallery_count,
        description,
        is_published,
        created_at
      from public.app_catalog_items
      where slug = $1
        and is_published = true
      limit 1
    `,
    [slug]
  );

  return rows[0] || null;
};
