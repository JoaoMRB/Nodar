// Copia para public/ o logo e os screenshots que já existem no repositório,
// para o site mostrar sempre as mesmas imagens que o README (sem cópias no git).
// Corre sozinho antes de `npm start` e `npm run build`.
import { cpSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const pub = join(site, 'public');

const copies = [
  [join(repo, 'docs/screenshots'), join(pub, 'screenshots/pt')],
  [join(repo, 'docs/screenshots/en'), join(pub, 'screenshots/en')],
];

rmSync(join(pub, 'screenshots'), { recursive: true, force: true });
for (const [from, to] of copies) {
  mkdirSync(to, { recursive: true });
  for (const f of readdirSync(from).filter((n) => n.endsWith('.png'))) cpSync(join(from, f), join(to, f));
}

const assets = join(repo, 'src/Nodar.App/Assets');
mkdirSync(join(pub, 'img'), { recursive: true });
for (const f of ['nodar-64.png', 'nodar-256.png']) cpSync(join(assets, f), join(pub, 'img', f));
cpSync(join(assets, 'nodar.ico'), join(pub, 'favicon.ico'));

console.log('assets: screenshots e logo copiados para public/');
