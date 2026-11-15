// 待确认：是否迁移至 Cloudflare CLI 构建管线；本构建脚本保持零 npm 依赖。
// 风险：输入模板中的占位标记需恰好出现一次；不读取网络、不修改 Cloudflare 账号。
// 验证重点：生成 worker.js 与源文件一致、语法可解析、重复构建字节一致。
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const base = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = [
  ['__PAGE_HTML__', 'src/page.html'],
  ['__SITE_CSS__', 'src/site.css'],
  ['__CLIENT_JS__', 'src/client.js'],
];
let output = readFileSync(path.join(base, 'src/edge.js'), 'utf8');
for (const [needle, source] of files) {
  const count = output.split(needle).length - 1;
  if (count !== 1) throw new Error('Invalid placeholder ' + needle + ': ' + count);
  output = output.replace(needle, JSON.stringify(readFileSync(path.join(base, source), 'utf8')));
}
writeFileSync(path.join(base, 'worker.js'), output);
console.log('Generated worker.js from src/* (single-file Cloudflare Worker).');
