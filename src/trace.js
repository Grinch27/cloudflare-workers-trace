// 待确认：上线后的外部解析器。歧义：JS 中的未定义字段沿用 JSON 序列化语义。
// 后续研究：根据外部使用情况评估格式版本。潜在优化：用实际报告大小核对编码开销。
// 风险：完整文本包含请求可见原值。验证重点：一行一字段，路径无歧义，转义保留原值。

function jsonLine(value) {
  return JSON.stringify(value).replace(/[\u0085\u2028-\u202e\u2066-\u2069]/g,
    character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'));
}

function objectPath(parent, key) {
  if (/^[a-zA-Z_][a-zA-Z0-9_-]*$/.test(key)) return parent ? parent + '.' + key : key;
  return parent + '[' + jsonLine(key).replaceAll('=', '\\u003d') + ']';
}

function writeField(lines, path, value) {
  if (Array.isArray(value) && value.length) {
    for (let index = 0; index < value.length; index++) {
      writeField(lines, path + '[' + index + ']', value[index] ?? null);
    }
    return;
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined);
    if (entries.length) {
      for (const [key, item] of entries) writeField(lines, objectPath(path, key), item);
      return;
    }
  }

  lines.push(path + '=' + jsonLine(value));
}

export function formatTrace(report, prefix = 'traceVersion=1\n') {
  const lines = [];
  for (const [key, value] of Object.entries(report)) {
    if (value !== undefined) writeField(lines, objectPath('', key), value);
  }
  return lines.length ? prefix + lines.join('\n') + '\n' : prefix;
}

export function parseTrace(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const separator = line.indexOf('=');
    const key = line.slice(0, separator);
    if (separator < 1 || fields.has(key)) throw new SyntaxError('Invalid or duplicate trace field');
    fields.set(key, JSON.parse(line.slice(separator + 1)));
  }
  return fields;
}
