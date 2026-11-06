import crypto from 'node:crypto';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import { getDatabase } from '@netlify/database';
import { getStore } from '@netlify/blobs';

const COOKIE_NAME = 'kut.sid';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_TOTAL_UPLOAD_BYTES = 3.2 * 1024 * 1024;
const MAX_FILES = 6; // one employee photo + up to five passport scans
const MAX_FILE_BYTES = 3 * 1024 * 1024;
const BLOB_STORE_NAME = 'kut-private-employee-files';
const BLOB_REGION = 'us-east-2'; // colocate with Netlify's default Functions region

let database;
let blobs;
function db() {
  if (!database) database = getDatabase();
  return database;
}
function store() {
  if (!blobs) blobs = getStore(BLOB_STORE_NAME, { region: BLOB_REGION });
  return blobs;
}
function pool() { return db().pool; }

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'private, no-store, max-age=0',
      'Pragma': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}
function plain(text, status = 200, headers = {}) {
  return new Response(text, { status, headers: { 'Cache-Control': 'private, no-store', ...headers } });
}
function getSecret(name, minLength = 32) {
  const value = process.env[name] || '';
  if (value.length < minLength) throw new Error(`Не настроена переменная ${name} в Netlify.`);
  return value;
}
function encryptionKey() {
  const key = Buffer.from(getSecret('KUT_DATA_ENCRYPTION_KEY', 40), 'base64');
  if (key.length !== 32) throw new Error('KUT_DATA_ENCRYPTION_KEY должна содержать Base64-кодированный ключ из 32 байт.');
  return key;
}
function encryptBuffer(input) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
}
function decryptBuffer(input) {
  if (!Buffer.isBuffer(input) || input.length < 29) throw new Error('Зашифрованный файл повреждён.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), input.subarray(0, 12));
  decipher.setAuthTag(input.subarray(12, 28));
  return Buffer.concat([decipher.update(input.subarray(28)), decipher.final()]);
}
function encryptJson(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const body = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), 'utf8')), cipher.final()]);
  return JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), body: body.toString('base64') });
}
function decryptJson(value) {
  const item = JSON.parse(value);
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(item.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(item.tag, 'base64'));
  const raw = Buffer.concat([decipher.update(Buffer.from(item.body, 'base64')), decipher.final()]).toString('utf8');
  return JSON.parse(raw);
}
function b64url(value) { return Buffer.from(value).toString('base64url'); }
function signToken(user) {
  const payload = b64url(JSON.stringify({
    id: String(user.id), username: user.username, role: user.role,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  }));
  const signature = crypto.createHmac('sha256', getSecret('KUT_SESSION_SECRET')).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function verifyToken(token) {
  if (!token || token.length > 4096) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  let expected;
  try {
    expected = crypto.createHmac('sha256', getSecret('KUT_SESSION_SECRET')).update(parts[0]).digest('base64url');
  } catch { return null; }
  if (!safeEqual(parts[1], expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!payload.id || !payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
function cookieHeader(token) {
  const secure = process.env.NETLIFY_DEV === 'true' ? '' : '; Secure';
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
}
function clearCookieHeader() {
  const secure = process.env.NETLIFY_DEV === 'true' ? '' : '; Secure';
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}
function requestedWith(req) {
  if (req.headers.get('x-requested-with') !== 'XMLHttpRequest') return false;
  const origin = req.headers.get('origin');
  if (origin) {
    try { if (new URL(origin).host !== new URL(req.url).host) return false; }
    catch { return false; }
  }
  return true;
}
async function requireAuth(req) {
  const token = parseCookies(req.headers.get('cookie') || '')[COOKIE_NAME];
  const payload = verifyToken(token);
  if (!payload) return null;
  const result = await pool().query('SELECT id, username, role, active FROM users WHERE id = $1', [payload.id]);
  const user = result.rows[0];
  if (!user || !user.active) return null;
  return { id: String(user.id), username: user.username, role: user.role };
}
function requireAdmin(user) { return user?.role === 'admin'; }
async function bodyJson(req) {
  try { return await req.json(); }
  catch { throw Object.assign(new Error('Неверный формат данных запроса.'), { status: 400 }); }
}
function normalizeFileName(name) {
  const base = path.basename(String(name || 'document')).replace(/[\r\n"'\\/]/g, '_').replace(/[\x00-\x1f]/g, '').trim();
  return (base || 'document').slice(0, 160);
}
function detectFileType(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return 'image/png';
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  if (buffer.length >= 5 && buffer.toString('ascii', 0, 5) === '%PDF-') return 'application/pdf';
  return null;
}
async function parseUploads(form) {
  const photoValue = form.get('photoFile');
  const photo = photoValue && typeof photoValue.arrayBuffer === 'function' && photoValue.size > 0 ? photoValue : null;
  const passports = form.getAll('passportFiles').filter(f => f && typeof f.arrayBuffer === 'function' && f.size > 0);
  if (passports.length > 5 || (photo ? 1 : 0) + passports.length > MAX_FILES) {
    throw Object.assign(new Error('Можно прикрепить одно фото и не более пяти файлов паспорта.'), { status: 400 });
  }
  const all = [...(photo ? [{ file: photo, field: 'photo' }] : []), ...passports.map(file => ({ file, field: 'passport' }))];
  const totalBytes = all.reduce((n, item) => n + item.file.size, 0);
  if (totalBytes > MAX_TOTAL_UPLOAD_BYTES) {
    throw Object.assign(new Error('Общий размер фото и паспортных файлов не должен превышать 3,2 МБ. Уменьшите размер скана и повторите загрузку.'), { status: 413 });
  }
  const out = { photo: null, passports: [] };
  for (const item of all) {
    const file = item.file;
    if (file.size > MAX_FILE_BYTES) throw Object.assign(new Error(`Файл «${normalizeFileName(file.name)}» больше 3 МБ.`), { status: 413 });
    const buffer = Buffer.from(await file.arrayBuffer());
    const detected = detectFileType(buffer);
    if (!detected) throw Object.assign(new Error(`Не удалось проверить формат файла «${normalizeFileName(file.name)}». Используйте JPG, PNG, WEBP или PDF.`), { status: 400 });
    if (item.field === 'photo' && detected === 'application/pdf') throw Object.assign(new Error('Фото сотрудника должно быть изображением.'), { status: 400 });
    const declared = String(file.type || '').toLowerCase();
    if (declared && declared !== detected && !(declared === 'image/jpg' && detected === 'image/jpeg')) {
      throw Object.assign(new Error(`Содержимое файла «${normalizeFileName(file.name)}» не совпадает с его типом.`), { status: 400 });
    }
    const prepared = { buffer, mimeType: detected, originalName: normalizeFileName(file.name), size: buffer.length };
    if (item.field === 'photo') out.photo = prepared;
    else out.passports.push(prepared);
  }
  return out;
}
async function saveEncryptedBlob(key, buffer) {
  const encrypted = encryptBuffer(buffer);
  await store().set(key, new Blob([encrypted]));
}
async function readEncryptedBlob(key) {
  const item = await store().get(key, { type: 'arrayBuffer' });
  if (!item) return null;
  return decryptBuffer(Buffer.from(item));
}
async function deleteBlob(key) {
  if (!key) return;
  try { await store().delete(key); } catch (error) { console.error('Blob cleanup failed', error); }
}
async function addUploadedFiles(employeeId, uploads) {
  const created = { photoKey: null, photoMime: null, docs: [], keys: [] };
  try {
    if (uploads.photo) {
      created.photoKey = `employee/${employeeId}/photo-${crypto.randomUUID()}`;
      created.photoMime = uploads.photo.mimeType;
      await saveEncryptedBlob(created.photoKey, uploads.photo.buffer);
      created.keys.push(created.photoKey);
    }
    for (const file of uploads.passports) {
      const key = `employee/${employeeId}/document-${crypto.randomUUID()}`;
      await saveEncryptedBlob(key, file.buffer);
      created.keys.push(key);
      created.docs.push({ id: crypto.randomUUID(), storageKey: key, originalName: file.originalName, mimeType: file.mimeType, size: file.size });
    }
    return created;
  } catch (error) {
    await Promise.all(created.keys.map(deleteBlob));
    throw error;
  }
}
async function withTransaction(fn) {
  const client = await pool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* ignore rollback failure */ }
    throw error;
  } finally { client.release(); }
}
function iso(value) { return value instanceof Date ? value.toISOString() : (value || ''); }
function decodeEmployee(row, docs = []) {
  const data = decryptJson(row.data_enc);
  return {
    ...data,
    id: row.id,
    photo: row.photo_key ? `/api/employees/${encodeURIComponent(row.id)}/photo` : '',
    passportFiles: docs,
    createdAt: iso(row.created_at),
    createdBy: String(row.created_by),
    createdByName: row.created_by_username || 'Сотрудник',
    approvalStatus: row.approval_status || 'pending',
    approvedBy: row.approved_by ? String(row.approved_by) : null,
    approvedByName: row.approved_by_username || '',
    approvedAt: iso(row.approved_at),
    rejectedBy: row.rejected_by ? String(row.rejected_by) : null,
    rejectedByName: row.rejected_by_username || '',
    rejectedAt: iso(row.rejected_at),
    rejectionReason: row.rejection_reason || '',
  };
}
async function listEmployees(user) {
  const rows = await pool().query(`
    SELECT e.*, creator.username AS created_by_username,
      approver.username AS approved_by_username, rejecter.username AS rejected_by_username
    FROM employees e
    LEFT JOIN users creator ON creator.id=e.created_by
    LEFT JOIN users approver ON approver.id=e.approved_by
    LEFT JOIN users rejecter ON rejecter.id=e.rejected_by
    ORDER BY e.created_at, e.id
  `);
  const docs = await pool().query('SELECT id, employee_id, original_name, mime_type, byte_size FROM documents ORDER BY created_at, id');
  const grouped = new Map();
  for (const d of docs.rows) {
    const key = String(d.employee_id);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push({ id: d.id, name: d.original_name, mime: d.mime_type, size: Number(d.byte_size) });
  }
  return rows.rows.map(row => {
    const docsForEmployee = grouped.get(String(row.id)) || [];
    const decoded = decodeEmployee(row, docsForEmployee);
    const uid = String(user.id);
    const canViewPassportData = user.role === 'admin'
      || uid === String(row.created_by)
      || (row.approval_status === 'pending' && uid !== String(row.created_by))
      || (row.approval_status === 'approved' && uid === String(row.approved_by))
      || (row.approval_status === 'rejected' && uid === String(row.rejected_by));
    if (!canViewPassportData) {
      decoded.docNo = '';
      decoded.birthDate = '';
      decoded.expiryDate = '';
      decoded.passportFiles = [];
      decoded.passportRestricted = docsForEmployee.length > 0;
    }
    return decoded;
  });
}
async function findEmployeeFileRow(employeeId) {
  const result = await pool().query(`
    SELECT id, photo_key, data_enc, created_by, approval_status, approved_by, rejected_by
    FROM employees WHERE id=$1
  `, [employeeId]);
  return result.rows[0] || null;
}
async function getEmployeePhotoAccess(user, employeeId) {
  const row = await findEmployeeFileRow(employeeId);
  if (!row) return { status: 404 };
  const uid = String(user.id);
  // Every authenticated operator needs to see an approved employee photo
  // so that the shared, approved pass can be previewed and printed.
  const allowed = user.role === 'admin'
    || uid === String(row.created_by)
    || row.approval_status === 'approved'
    || (row.approval_status === 'pending' && uid !== String(row.created_by))
    || (row.approval_status === 'rejected' && uid === String(row.rejected_by));
  if (!allowed) return { status: 403 };
  return { row };
}
async function getEmployeeDocumentAccess(user, employeeId) {
  const row = await findEmployeeFileRow(employeeId);
  if (!row) return { status: 404 };
  const uid = String(user.id);
  // Passport scans remain restricted even when the pass itself is approved.
  const allowed = user.role === 'admin'
    || uid === String(row.created_by)
    || (row.approval_status === 'pending' && uid !== String(row.created_by))
    || (row.approval_status === 'approved' && uid === String(row.approved_by))
    || (row.approval_status === 'rejected' && uid === String(row.rejected_by));
  if (!allowed) return { status: 403 };
  return { row };
}
function attachmentName(name) {
  const safeAscii = String(name || 'document').replace(/[^\x20-\x7E]/g, '_').replace(/["\\;]/g, '_').slice(0, 100) || 'document';
  return `attachment; filename="${safeAscii}"; filename*=UTF-8''${encodeURIComponent(String(name || 'document'))}`;
}
async function route(req, user, pathname) {
  const method = req.method.toUpperCase();
  const parts = pathname.split('/').filter(Boolean).map(part => decodeURIComponent(part));
  // The function is mounted at /api/*, so remove the first segment.
  if (parts[0] === 'api') parts.shift();
  const routePath = '/' + parts.join('/');

  if (routePath === '/healthz' && method === 'GET') return json({ ok: true, service: 'kut-netlify-api' });

  if (routePath === '/setup' && method === 'POST') {
    const configuredToken = process.env.KUT_SETUP_TOKEN || '';
    if (configuredToken.length < 24) return json({ error: 'Сначала добавьте KUT_SETUP_TOKEN в переменные окружения Netlify.' }, 503);
    const body = await bodyJson(req);
    if (!safeEqual(String(body.setupToken || ''), configuredToken)) return json({ error: 'Неверный код первоначальной настройки.' }, 403);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return json({ error: 'Логин: 3–40 символов, латиница, цифры, точка, _ или -.' }, 400);
    if (password.length < 14) return json({ error: 'Пароль администратора должен содержать не менее 14 символов.' }, 400);
    const hash = await bcrypt.hash(password, 12);
    try {
      const created = await withTransaction(async client => {
        await client.query('LOCK TABLE users IN EXCLUSIVE MODE');
        const count = await client.query('SELECT COUNT(*)::int AS n FROM users');
        if (count.rows[0].n > 0) return false;
        await client.query(
          'INSERT INTO users(username,password_hash,role,active,created_at) VALUES($1,$2,$3,true,NOW())',
          [username, hash, 'admin']);
        return true;
      });
      if (!created) return json({ error: 'Первичная настройка уже завершена. Создавать ещё одного администратора здесь нельзя.' }, 409);
      return json({ ok: true, message: 'Администратор создан. Теперь войдите в систему.' }, 201);
    } catch (error) {
      if (error.code === '23505') return json({ error: 'Такой логин уже существует.' }, 409);
      throw error;
    }
  }

  if (routePath === '/login' && method === 'POST') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    const body = await bodyJson(req);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    if (!username || !password || username.length > 40 || password.length > 256) return json({ error: 'Введите логин и пароль.' }, 400);
    const ip = req.headers.get('x-nf-client-connection-ip') || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
    const ipHash = crypto.createHmac('sha256', getSecret('KUT_SESSION_SECRET')).update(ip).digest('hex');
    const limits = await pool().query('SELECT attempts, window_started FROM login_attempts WHERE ip_hash=$1', [ipHash]);
    if (limits.rows[0] && new Date(limits.rows[0].window_started).getTime() > Date.now() - 15 * 60 * 1000 && Number(limits.rows[0].attempts) >= 12) {
      return json({ error: 'Слишком много попыток входа. Попробуйте через 15 минут.' }, 429);
    }
    const found = await pool().query('SELECT id, username, password_hash, role, active FROM users WHERE lower(username)=lower($1)', [username]);
    const userRow = found.rows[0];
    const valid = !!(userRow && userRow.active && await bcrypt.compare(password, userRow.password_hash));
    if (!valid) {
      await pool().query(`INSERT INTO login_attempts(ip_hash,attempts,window_started) VALUES($1,1,NOW())
        ON CONFLICT(ip_hash) DO UPDATE SET
          attempts=CASE WHEN login_attempts.window_started < NOW() - INTERVAL '15 minutes' THEN 1 ELSE login_attempts.attempts + 1 END,
          window_started=CASE WHEN login_attempts.window_started < NOW() - INTERVAL '15 minutes' THEN NOW() ELSE login_attempts.window_started END`, [ipHash]);
      return json({ error: 'Неверный логин или пароль.' }, 401);
    }
    await pool().query('DELETE FROM login_attempts WHERE ip_hash=$1', [ipHash]);
    const token = signToken({ id: userRow.id, username: userRow.username, role: userRow.role });
    return json({ user: { id: String(userRow.id), username: userRow.username, role: userRow.role } }, 200, { 'Set-Cookie': cookieHeader(token) });
  }

  if (routePath === '/logout' && method === 'POST') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    if (!user) return json({ ok: true }, 200, { 'Set-Cookie': clearCookieHeader() });
    return json({ ok: true }, 200, { 'Set-Cookie': clearCookieHeader() });
  }

  if (!user) return json({ error: 'Требуется вход в систему.' }, 401);
  if (routePath === '/me' && method === 'GET') return json({ user });

  if (routePath === '/employees' && method === 'GET') {
    return json({ employees: await listEmployees(user), user });
  }

  if (routePath === '/employees' && method === 'POST') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    let form, uploads;
    try {
      form = await req.formData();
      uploads = await parseUploads(form);
    } catch (error) { return json({ error: error.message || 'Не удалось прочитать файлы.' }, error.status || 400); }
    return await createEmployeeFromForm(uploads, form, user);
  }

  const approveMatch = routePath.match(/^\/employees\/([^/]+)\/(approve|reject)$/);
  if (approveMatch && method === 'POST') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    const employeeId = approveMatch[1];
    const action = approveMatch[2];
    const body = action === 'reject' ? await bodyJson(req) : {};
    return await reviewEmployee(employeeId, action, String(body.comment || '').trim().slice(0, 500), user);
  }

  const photoMatch = routePath.match(/^\/employees\/([^/]+)\/photo$/);
  if (photoMatch && method === 'GET') {
    const access = await getEmployeePhotoAccess(user, photoMatch[1]);
    if (access.status) return json({ error: access.status === 403 ? 'Нет доступа к этому фото.' : 'Сотрудник не найден.' }, access.status);
    if (!access.row.photo_key) return plain('Not found', 404);
    const data = decryptJson(access.row.data_enc);
    const buffer = await readEncryptedBlob(access.row.photo_key);
    if (!buffer) return plain('Not found', 404);
    return new Response(buffer, { status: 200, headers: {
      'Content-Type': data.photoMime || 'image/jpeg', 'Content-Length': String(buffer.length),
      'Content-Disposition': 'inline; filename="employee-photo"', 'Cache-Control': 'private, no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin',
    }});
  }

  const docMatch = routePath.match(/^\/employees\/([^/]+)\/documents\/([^/]+)$/);
  if (docMatch && method === 'GET') {
    const access = await getEmployeeDocumentAccess(user, docMatch[1]);
    if (access.status) return json({ error: access.status === 403 ? 'Нет доступа к этому документу.' : 'Сотрудник не найден.' }, access.status);
    const found = await pool().query('SELECT storage_key,original_name,mime_type FROM documents WHERE id=$1 AND employee_id=$2', [docMatch[2], docMatch[1]]);
    if (!found.rows[0]) return plain('Not found', 404);
    const doc = found.rows[0];
    const buffer = await readEncryptedBlob(doc.storage_key);
    if (!buffer) return plain('Not found', 404);
    return new Response(buffer, { status: 200, headers: {
      'Content-Type': doc.mime_type, 'Content-Length': String(buffer.length),
      'Content-Disposition': attachmentName(doc.original_name), 'Cache-Control': 'private, no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin',
    }});
  }

  const editMatch = routePath.match(/^\/employees\/([^/]+)$/);
  if (editMatch && method === 'PUT') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    let form;
    try { form = await req.formData(); }
    catch { return json({ error: 'Не удалось прочитать форму. Проверьте размер файлов.' }, 400); }
    let uploads;
    try { uploads = await parseUploads(form); }
    catch (error) { return json({ error: error.message || 'Не удалось прочитать файлы.' }, error.status || 400); }
    return await updateEmployee(editMatch[1], form, uploads, user);
  }

  if (editMatch && method === 'DELETE') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    if (!requireAdmin(user)) return json({ error: 'Недостаточно прав.' }, 403);
    const removed = await withTransaction(async client => {
      const row = await client.query('SELECT photo_key FROM employees WHERE id=$1 FOR UPDATE', [editMatch[1]]);
      if (!row.rows[0]) return null;
      const docs = await client.query('SELECT storage_key FROM documents WHERE employee_id=$1', [editMatch[1]]);
      await client.query('DELETE FROM employees WHERE id=$1', [editMatch[1]]);
      return [row.rows[0].photo_key, ...docs.rows.map(x => x.storage_key)].filter(Boolean);
    });
    if (!removed) return json({ error: 'Сотрудник не найден.' }, 404);
    await Promise.all(removed.map(deleteBlob));
    return json({ ok: true });
  }

  if (routePath === '/employees' && method === 'DELETE') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    if (!requireAdmin(user)) return json({ error: 'Недостаточно прав.' }, 403);
    const keys = await withTransaction(async client => {
      const rows = await client.query('SELECT photo_key FROM employees WHERE photo_key IS NOT NULL');
      const docs = await client.query('SELECT storage_key FROM documents');
      await client.query('DELETE FROM employees');
      return [...rows.rows.map(x => x.photo_key), ...docs.rows.map(x => x.storage_key)].filter(Boolean);
    });
    await Promise.all(keys.map(deleteBlob));
    return json({ ok: true });
  }

  if (routePath === '/users' && method === 'GET') {
    if (!requireAdmin(user)) return json({ error: 'Недостаточно прав.' }, 403);
    const rows = await pool().query('SELECT id,username,role,active,created_at FROM users ORDER BY id');
    return json({ users: rows.rows.map(u => ({ id: Number(u.id), username: u.username, role: u.role, active: u.active, createdAt: iso(u.created_at) })) });
  }

  if (routePath === '/users' && method === 'POST') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    if (!requireAdmin(user)) return json({ error: 'Недостаточно прав.' }, 403);
    const body = await bodyJson(req);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const role = body.role === 'admin' ? 'admin' : 'operator';
    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return json({ error: 'Логин: от 3 до 40 символов (латиница, цифры, точка, _ или -).' }, 400);
    if (password.length < 12) return json({ error: 'Пароль должен содержать не менее 12 символов.' }, 400);
    const hash = await bcrypt.hash(password, 12);
    try {
      const result = await pool().query('INSERT INTO users(username,password_hash,role,active,created_at) VALUES($1,$2,$3,true,NOW()) RETURNING id', [username, hash, role]);
      return json({ ok: true, id: Number(result.rows[0].id) }, 201);
    } catch (error) {
      if (error.code === '23505') return json({ error: 'Такой логин уже существует.' }, 409);
      throw error;
    }
  }

  const userMatch = routePath.match(/^\/users\/([^/]+)$/);
  if (userMatch && method === 'DELETE') {
    if (!requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    if (!requireAdmin(user)) return json({ error: 'Недостаточно прав.' }, 403);
    const targetId = userMatch[1];
    if (String(targetId) === String(user.id)) return json({ error: 'Нельзя отключить свою учётную запись во время работы.' }, 400);
    const target = await pool().query('SELECT id,role,active FROM users WHERE id=$1', [targetId]);
    if (!target.rows[0]) return plain('Not found', 404);
    if (target.rows[0].role === 'admin' && target.rows[0].active) {
      const count = await pool().query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin' AND active=true");
      if (count.rows[0].n <= 1) return json({ error: 'Нельзя отключить последнего активного администратора.' }, 400);
    }
    await pool().query('UPDATE users SET active=false WHERE id=$1', [targetId]);
    return json({ ok: true });
  }

  return json({ error: 'Маршрут не найден.' }, 404);
}

async function createEmployeeFromForm(uploads, form, user) {
  // form may be null only if the request body was consumed incorrectly; this path is guarded below.
  if (!form) return json({ error: 'Не удалось прочитать поля формы. Повторите отправку.' }, 400);
  const field = name => String(form.get(name) || '').trim();
  const surname = field('surname'), given = field('given'), middle = field('middle');
  const job = field('job'), dept = field('dept');
  if (!surname || !given || !job || !dept) return json({ error: 'Заполните фамилию, имя, отдел и должность.' }, 400);
  if (!uploads.passports.length) return json({ error: 'Прикрепите хотя бы один скан паспорта или ID-карты.' }, 400);
  const id = crypto.randomUUID();
  const files = await addUploadedFiles(id, uploads);
  try {
    const createdAt = new Date().toISOString();
    const result = await withTransaction(async client => {
      let num = field('num');
      if (!num) {
        await client.query('LOCK TABLE employees IN SHARE ROW EXCLUSIVE MODE');
        const count = await client.query('SELECT COUNT(*)::int AS n FROM employees');
        num = String(count.rows[0].n + 1).padStart(4, '0');
      }
      const data = {
        surname, given, middle, fio: [surname, given, middle].filter(Boolean).join(' '),
        docNo: field('docNo'), birthDate: field('birthDate'), expiryDate: field('expiryDate'),
        photoMime: files.photoMime || 'image/jpeg', dept, num,
        date: field('date') || new Date().toISOString().slice(0, 10), job,
      };
      await client.query(`INSERT INTO employees(id,data_enc,photo_key,created_at,created_by,approval_status)
        VALUES($1,$2,$3,$4,$5,'pending')`, [id, encryptJson(data), files.photoKey, createdAt, user.id]);
      for (const doc of files.docs) {
        await client.query(`INSERT INTO documents(id,employee_id,storage_key,original_name,mime_type,byte_size,created_at)
          VALUES($1,$2,$3,$4,$5,$6,NOW())`, [doc.id, id, doc.storageKey, doc.originalName, doc.mimeType, doc.size]);
      }
      await client.query(`INSERT INTO approval_events(employee_id,actor_id,action,comment,created_at)
        VALUES($1,$2,'submitted',NULL,$3)`, [id, user.id, createdAt]);
      return true;
    });
    return json({ ok: true, id, approvalStatus: 'pending' }, 201);
  } catch (error) {
    await Promise.all(files.keys.map(deleteBlob));
    throw error;
  }
}

async function updateEmployee(id, form, uploads, user) {
  const field = name => String(form.get(name) || '').trim();
  const surname = field('surname'), given = field('given'), middle = field('middle');
  const job = field('job'), dept = field('dept');
  if (!surname || !given || !job || !dept) return json({ error: 'Заполните фамилию, имя, отдел и должность.' }, 400);
  const existingResult = await pool().query('SELECT * FROM employees WHERE id=$1', [id]);
  const existing = existingResult.rows[0];
  if (!existing) return json({ error: 'Сотрудник не найден.' }, 404);
  if (String(existing.created_by) !== String(user.id)) return json({ error: 'Исправлять эту запись может только сотрудник, который её создал.' }, 403);
  if (existing.approval_status !== 'rejected') return json({ error: 'Исправлять можно только запись, возвращённую на доработку.' }, 409);
  const existingDocs = await pool().query('SELECT id FROM documents WHERE employee_id=$1', [id]);
  if (!uploads.passports.length && existingDocs.rowCount === 0) return json({ error: 'Прикрепите хотя бы один скан паспорта или ID-карты.' }, 400);
  const files = await addUploadedFiles(id, uploads);
  const oldKeys = [];
  try {
    await withTransaction(async client => {
      const locked = await client.query('SELECT created_by,approval_status,photo_key,data_enc FROM employees WHERE id=$1 FOR UPDATE', [id]);
      if (!locked.rows[0]) throw Object.assign(new Error('Сотрудник не найден.'), { status: 404 });
      if (String(locked.rows[0].created_by) !== String(user.id)) throw Object.assign(new Error('Исправлять эту запись может только её автор.'), { status: 403 });
      if (locked.rows[0].approval_status !== 'rejected') throw Object.assign(new Error('Эта запись уже не ожидает исправления.'), { status: 409 });
      const oldData = decryptJson(locked.rows[0].data_enc);
      const data = {
        ...oldData, surname, given, middle, fio: [surname, given, middle].filter(Boolean).join(' '),
        docNo: field('docNo'), birthDate: field('birthDate'), expiryDate: field('expiryDate'),
        photoMime: files.photoMime || oldData.photoMime || 'image/jpeg', dept,
        num: field('num') || oldData.num || '',
        date: field('date') || oldData.date || new Date().toISOString().slice(0, 10), job,
      };
      const photoKey = files.photoKey || locked.rows[0].photo_key;
      await client.query(`UPDATE employees SET data_enc=$1,photo_key=$2,approval_status='pending',
        approved_by=NULL,approved_at=NULL,rejected_by=NULL,rejected_at=NULL,rejection_reason=NULL WHERE id=$3`,
        [encryptJson(data), photoKey, id]);
      if (uploads.passports.length) {
        const oldDocs = await client.query('SELECT storage_key FROM documents WHERE employee_id=$1', [id]);
        oldKeys.push(...oldDocs.rows.map(x => x.storage_key));
        await client.query('DELETE FROM documents WHERE employee_id=$1', [id]);
        for (const doc of files.docs) {
          await client.query(`INSERT INTO documents(id,employee_id,storage_key,original_name,mime_type,byte_size,created_at)
            VALUES($1,$2,$3,$4,$5,$6,NOW())`, [doc.id, id, doc.storageKey, doc.originalName, doc.mimeType, doc.size]);
        }
      }
      if (files.photoKey && locked.rows[0].photo_key) oldKeys.push(locked.rows[0].photo_key);
      await client.query(`INSERT INTO approval_events(employee_id,actor_id,action,comment,created_at)
        VALUES($1,$2,'submitted','Повторно отправлено после исправления',NOW())`, [id, user.id]);
    });
    await Promise.all(oldKeys.map(deleteBlob));
    return json({ ok: true, approvalStatus: 'pending' });
  } catch (error) {
    await Promise.all(files.keys.map(deleteBlob));
    if (error.status) return json({ error: error.message }, error.status);
    throw error;
  }
}

async function reviewEmployee(id, action, comment, user) {
  if (action === 'reject' && comment.length < 3) return json({ error: 'Укажите причину возврата (минимум 3 символа).' }, 400);
  return await withTransaction(async client => {
    const result = await client.query('SELECT created_by,approval_status FROM employees WHERE id=$1 FOR UPDATE', [id]);
    const employee = result.rows[0];
    if (!employee) return json({ error: 'Сотрудник не найден.' }, 404);
    if (String(employee.created_by) === String(user.id)) return json({ error: 'Нельзя подтвердить или вернуть собственную запись. Это должен сделать другой сотрудник под своим логином.' }, 403);
    if (employee.approval_status !== 'pending') return json({ error: 'Эта запись уже обработана другим сотрудником.' }, 409);
    const now = new Date().toISOString();
    if (action === 'approve') {
      await client.query(`UPDATE employees SET approval_status='approved',approved_by=$1,approved_at=$2,
        rejected_by=NULL,rejected_at=NULL,rejection_reason=NULL WHERE id=$3`, [user.id, now, id]);
      await client.query(`INSERT INTO approval_events(employee_id,actor_id,action,comment,created_at) VALUES($1,$2,'approved',NULL,$3)`, [id, user.id, now]);
      return json({ ok: true, message: 'Пропуск подтверждён. Теперь он доступен для печати.' });
    }
    await client.query(`UPDATE employees SET approval_status='rejected',rejected_by=$1,rejected_at=$2,rejection_reason=$3 WHERE id=$4`, [user.id, now, comment, id]);
    await client.query(`INSERT INTO approval_events(employee_id,actor_id,action,comment,created_at) VALUES($1,$2,'rejected',$3,$4)`, [id, user.id, comment, now]);
    return json({ ok: true, message: 'Запись возвращена с замечанием.' });
  });
}

export default async (req) => {
  try {
    const url = new URL(req.url);
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    if (req.method.toUpperCase() !== 'GET' && !requestedWith(req)) return json({ error: 'Запрос отклонён.' }, 403);
    let user = null;
    if (!['/api/login', '/api/setup', '/api/healthz'].includes(pathname)) user = await requireAuth(req);
    return await route(req, user, pathname);
  } catch (error) {
    console.error('KUT API error:', error);
    const status = Number(error.status) || 500;
    return json({ error: status >= 500 ? 'Внутренняя ошибка сервера. Проверьте настройки Netlify и базы данных.' : error.message }, status);
  }
};

export const config = { path: '/api/*' };
