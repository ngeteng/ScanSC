/**
 * anti-logger.js v1.1.0
 * 
 * CLI tool untuk scan file .js/.jsx mencari pola-pola API
 * yang sering dipakai untuk mencuri/leak data:
 * - fetch, XMLHttpRequest, axios, WebSocket, sendBeacon
 * - document.cookie, localStorage, sessionStorage
 * - eval/Function dengan URL/string dinamis
 * - panggilan ke Telegram Bot API, Discord Webhook, Facebook Graph API
 */

#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const glob = require('glob');
const espree = require('espree');
const estraverse = require('estraverse');
const chalk = require('chalk');
const { Command } = require('commander');

const program = new Command();
program
  .name('anti-logger')
  .description('Scan JS files for potential data-leak/logging APIs')
  .version('1.1.0')
  .argument('<pattern>', 'Glob pattern to JavaScript files, e.g. "src/**/*.js"')
  .parse(process.argv);

const [pattern] = program.args;
if (!pattern) {
  console.error(chalk.red('❌ Masukkan pattern file, misal: src/**/*.js'));
  process.exit(1);
}

// daftar fungsi/pola yang mau di-scan
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
// domain patterns for external services
const externalServices = [
  /https?:\/\/(api\.)?telegram\.org\//i,
  /https?:\/\/discord\.com\/api\/webhooks\//i,
  /https?:\/\/graph\.facebook\.com\//i
];

function isSuspiciousNode(node, code) {
  // cek fungsi/pola AST
  for (const s of suspicious) {
    if (node.type === s.type) {
      if (s.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === s.name) return true;
      if (s.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === s.name) return true;
      if (s.type === 'MemberExpression') {
        const left = node.object && node.object.name;
        const right = node.property && node.property.name;
        if (`${left}.${right}` === s.name) return true;
      }
      if (s.name === 'axios' && node.callee.type === 'MemberExpression' && node.callee.object.name === 'axios') return true;
    }
  }
  // cek literal string URL untuk external services
  if (node.type === 'Literal' && typeof node.value === 'string') {
    for (const re of externalServices) {
      if (re.test(node.value)) return true;
    }
  }
  // cek template literal
  if (node.type === 'TemplateLiteral') {
    const raw = node.quasis.map(q => q.value.raw).join(' ');
    for (const re of externalServices) {
      if (re.test(raw)) return true;
    }
  }
  return false;
}

function scanFile(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  let ast;
  try {
    ast = espree.parse(code, { ecmaVersion: 'latest', sourceType: 'module', loc: true });
  } catch (err) {
    console.error(chalk.yellow(`⚠️  Gagal parse ${filePath}: ${err.message}`));
    return [];
  }

  const findings = [];
  estraverse.traverse(ast, {
    enter(node) {
      if (isSuspiciousNode(node, code)) {
        findings.push({
          line: node.loc.start.line,
          snippet: code.split('\n')[node.loc.start.line - 1].trim()
        });
      }
    }
  });

  return findings;
}

glob(pattern, { nodir: true }, (err, files) => {
  if (err) throw err;
  if (!files.length) {
    console.log(chalk.red('❌ Tidak ada file yang cocok dengan pattern.'), pattern);
    process.exit(1);
  }

  let total = 0;
  files.forEach(file => {
    const absolute = path.resolve(file);
    const results = scanFile(absolute);
    if (results.length) {
      console.log(chalk.blue.bold(`\n📄 ${file}`));
      results.forEach(f => {
        console.log(chalk.yellow(`  [baris ${f.line}]`), chalk.gray(f.snippet));
        total++;
      });
    }
  });

  console.log(chalk.green.bold(`\n✅ Selesai. Total temuan: ${total}`));
});
