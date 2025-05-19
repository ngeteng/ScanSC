#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const glob = require('glob');
const espree = require('espree');
const estraverse = require('estraverse');
const chalkImport = require('chalk');
const chalk = chalkImport.default ?? chalkImport;
const { Command } = require('commander');

// Use global fetch (Node.js v18+) or user must install node-fetch
const fetchFn = global.fetch || (async () => { throw new Error('Global fetch not available. Please use Node.js v18+ or install node-fetch'); })();

const program = new Command();
program
  .name('anti-logger')
  .description('Scan JS files or remote JS URLs for potential data-leak/logging APIs')
  .version('1.3.0')
  .argument('[pattern]', 'Glob pattern to JavaScript files, e.g. "src/**/*.js"')
  .option('--json', 'Output result in JSON format')
  .option('--url <url>', 'Scan a remote JavaScript file by URL')
  .parse(process.argv);

const opts = program.opts();
const [pattern] = program.args;

if (!pattern && !opts.url) {
  console.error(chalk.red('❌ Masukkan pattern file atau --url, misal: src/**/*.js atau --url https://example.com/script.js'));
  process.exit(1);
}

// Suspicious patterns (same as before)
const suspicious = [
  { type: 'CallExpression', name: 'fetch' },
  { type: 'NewExpression', name: 'XMLHttpRequest' },
  { type: 'MemberExpression', name: 'axios' },
  { type: 'NewExpression', name: 'WebSocket' },
  { type: 'CallExpression', name: 'sendBeacon' },
  { type: 'MemberExpression', name: 'document.cookie' },
  { type: 'MemberExpression', name: 'localStorage' },
  { type: 'MemberExpression', name: 'sessionStorage' },
  { type: 'CallExpression', name: 'eval' },
  { type: 'NewExpression', name: 'Function' }
];
const externalServices = [
  /https?:\/\/(api\.)?telegram\.org\//i,
  /https?:\/\/discord\.com\/api\/webhooks\//i,
  /https?:\/\/graph\.facebook\.com\//i,
  /https?:\/\/hooks\.slack\.com\//i
];

function isSuspiciousNode(node, axiosAliases) {
  for (const s of suspicious) {
    if (node.type === s.type) {
      if (
        s.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === s.name
      ) return true;
      if (
        s.type === 'NewExpression' && node.callee?.type === 'Identifier' && node.callee.name === s.name
      ) return true;
      if (s.type === 'MemberExpression') {
        const left = node.object?.name;
        const right = node.property?.name;
        if (`${left}.${right}` === s.name) return true;
      }
      if (
        s.name === 'axios' && node.callee?.type === 'MemberExpression' && node.callee.object?.name === 'axios'
      ) return true;
    }
  }
  if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' && axiosAliases.has(obj.name)) return true;
  }
  if (node.type === 'ImportExpression') return true;
  if (node.type === 'Literal' && typeof node.value === 'string') {
    for (const re of externalServices) if (re.test(node.value)) return true;
  }
  if (node.type === 'TemplateLiteral') {
    const raw = node.quasis.map(q => q.value.raw).join(' ');
    for (const re of externalServices) if (re.test(raw)) return true;
  }
  return false;
}

function scanCode(code) {
  let ast;
  try {
    ast = espree.parse(code, { ecmaVersion: 'latest', sourceType: 'module', loc: true });
  } catch (err) {
    console.error(chalk.yellow(`⚠️  Gagal parse input: ${err.message}`));
    return [];
  }
  const axiosAliases = new Set();
  estraverse.traverse(ast, { enter(node) {
    if (node.type === 'ImportDeclaration' && node.source.value === 'axios') {
      node.specifiers.forEach(spec => axiosAliases.add(spec.local.name));
    }
  }});

  const findings = [];
  estraverse.traverse(ast, { enter(node) {
    if (isSuspiciousNode(node, axiosAliases)) {
      findings.push({ line: node.loc.start.line, snippet: code.split('\n')[node.loc.start.line - 1].trim() });
    }
  }});
  return findings;
}

(async () => {
  const resultsByFile = {};
  let totalFindings = 0;

  if (opts.url) {
    try {
      const res = await fetchFn(opts.url);
      const code = await res.text();
      const findings = scanCode(code);
      if (findings.length) resultsByFile[opts.url] = findings;
      totalFindings = findings.length;
      outputResults(1, resultsByFile, totalFindings);
    } catch (err) {
      console.error(chalk.red(`❌ Gagal fetch URL: ${err.message}`));
      process.exit(1);
    }
  } else {
    glob(pattern, { nodir: true }, (err, files) => {
      if (err) throw err;
      if (!files.length) {
        console.error(chalk.red(`❌ Tidak ada file yang cocok dengan pattern: ${pattern}`));
        process.exit(1);
      }
      files.forEach(file => {
        const code = fs.readFileSync(path.resolve(file), 'utf8');
        const findings = scanCode(code);
        if (findings.length) {
          resultsByFile[file] = findings;
          totalFindings += findings.length;
        }
      });
      outputResults(files.length, resultsByFile, totalFindings);
    });
  }
})();

function outputResults(totalFiles, resultsByFile, totalFindings) {
  const filesWithFindings = Object.values(resultsByFile).filter(arr => arr.length > 0).length;
  if (opts.json) {
    console.log(JSON.stringify({ summary: { totalFiles, filesWithFindings, totalFindings }, details: resultsByFile }, null, 2));
  } else {
    Object.entries(resultsByFile).forEach(([key, findings]) => {
      console.log(chalk.blue(`\n📄 ${key} (temuan: ${findings.length})`));
      findings.forEach(f => console.log(chalk.yellow(`  [baris ${f.line}]`), chalk.gray(f.snippet)));
    });
    console.log(chalk.green(`\n✅ Selesai. Total file: ${totalFiles}, file dengan temuan: ${filesWithFindings}, total temuan: ${totalFindings}`));
  }
}
