import { access, readFile } from 'node:fs/promises';

const required = [
  'public/index.html',
  'public/login.html',
  'public/setup.html',
  'netlify/functions/api.mjs',
  'netlify/database/migrations/202611060001_initial_schema.sql',
];
for (const file of required) await access(new URL(`../${file}`, import.meta.url));
const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
if (!html.includes("fetch(url") || !html.includes("/api/employees")) {
  throw new Error('Не найден интерфейс API в public/index.html');
}
console.log('КУТ: файлы сайта, API и миграции базы на месте.');
