# Agro Maquinas Ipiranga

Site institucional com catálogo, página de detalhe, cadastro e login com autenticação JWT própria usando Supabase apenas como banco Postgres.

Repositório público:

- `https://github.com/rxsec/agromaquinasipiranga`

## Stack

- HTML, CSS e JavaScript
- Node.js + Express
- JWT próprio
- Supabase Postgres
- Vercel para frontend + funções `api/`

## Rodando localmente

1. Instale as dependências:

```bash
npm install
```

2. Crie seu arquivo local:

```bash
cp .env.example .env
```

3. Preencha o `.env`

4. Inicie:

```bash
npm start
```

5. Acesse:

- `http://localhost:3000`

## Banco no Supabase

Execute o SQL abaixo no `SQL Editor` do Supabase:

- [supabase/001_init.sql](/home/paulo-pereira/Área%20de%20trabalho/agro/supabase/001_init.sql)

Esse script cria:

- `public.app_users`
- `public.app_refresh_tokens`

Consulta rápida:

- [sql/check_profiles.sql](/home/paulo-pereira/Área%20de%20trabalho/agro/sql/check_profiles.sql)

## Variáveis de ambiente

Base local:

- [`.env.example`](/home/paulo-pereira/Área%20de%20trabalho/agro/.env.example)

Variáveis usadas:

- `DATABASE_URL`
- `DIRECT_URL`
- `JWT_SECRET`
- `JWT_EXPIRES_IN`
- `JWT_REFRESH_SECRET`
- `JWT_REFRESH_EXPIRES_IN`
- `BCRYPT_ROUNDS`
- `APP_ENV`
- `PORT`
- `APP_URL`
- `APP_DOMAIN`
- `CORS_ORIGIN`

## Como preencher na Vercel

No painel da Vercel:

1. Entre no projeto
2. Abra `Settings`
3. Abra `Environment Variables`
4. Cadastre estas chaves

### Cenário 1: domínio `.vercel.app`

Use assim:

- `DATABASE_URL`: sua connection string pooler
- `DIRECT_URL`: sua connection string direta
- `JWT_SECRET`: seu segredo forte
- `JWT_EXPIRES_IN`: `15m`
- `JWT_REFRESH_SECRET`: seu segredo forte de refresh
- `JWT_REFRESH_EXPIRES_IN`: `30d`
- `BCRYPT_ROUNDS`: `12`
- `APP_ENV`: `production`
- `PORT`: `3000`
- `APP_URL`: `https://SEU-PROJETO.vercel.app`
- `APP_DOMAIN`: `SEU-PROJETO.vercel.app`
- `CORS_ORIGIN`: `https://SEU-PROJETO.vercel.app`

### Cenário 2: domínio próprio final

Use assim:

- `DATABASE_URL`: sua connection string pooler
- `DIRECT_URL`: sua connection string direta
- `JWT_SECRET`: seu segredo forte
- `JWT_EXPIRES_IN`: `15m`
- `JWT_REFRESH_SECRET`: seu segredo forte de refresh
- `JWT_REFRESH_EXPIRES_IN`: `30d`
- `BCRYPT_ROUNDS`: `12`
- `APP_ENV`: `production`
- `PORT`: `3000`
- `APP_URL`: `https://agromaquinasipiranga.com.br`
- `APP_DOMAIN`: `agromaquinasipiranga.com.br`
- `CORS_ORIGIN`: `https://agromaquinasipiranga.com.br,https://www.agromaquinasipiranga.com.br`

## Deploy na Vercel

1. Importe o repositório `rxsec/agromaquinasipiranga`
2. Mantenha o framework como `Other`
3. Não precisa definir build command
4. Defina as variáveis de ambiente
5. Faça o deploy

O projeto já está preparado com:

- [vercel.json](/home/paulo-pereira/Área%20de%20trabalho/agro/vercel.json)
- rotas serverless em [api](/home/paulo-pereira/Área%20de%20trabalho/agro/api)

## APIs disponíveis

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
