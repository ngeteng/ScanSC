#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const glob = require('glob');
const espree = require('espree');
const estraverse = require('estraverse');
const chalk = require('chalk');
const { Command } = require('commander');
const os = require('os');

const program = new Command();
program
  .name('anti-logger')
  .description('Scan JS files for potential data-leak/logging APIs')
  .version('1.2.0')
  .argument('<pattern>', 'Glob pattern to JavaScript files, e.g. "src/**/*.js"')
  .option('--json', 'Output result in JSON format')
  .parse(process.argv);

const opts = program.opts();
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
  /https?:\/\/graph\.facebook\.com\//i,
  /https?:\/\/hooks\.slack\.com\//i
];

function isSuspiciousNode(node, axiosAliases) {
  // cek fungsi/pola AST
  for (const s of suspicious) {
    if (node.type === s.type) {
      // CallExpression
      if (
        s.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' &&
        node.callee.name === s.name
      ) return true;

      // NewExpression
      if (
        s.type === 'NewExpression' &&
        node.callee?.type === 'Identifier' &&
        node.callee.name === s.name
      ) return true;

      // MemberExpression
      if (s.type === 'MemberExpression') {
        const left = node.object?.name;
        const right = node.property?.name;
        if (`${left}.${right}` === s.name) return true;
      }

      // axios via MemberExpression
      if (
        s.name === 'axios' &&
        node.callee?.type === 'MemberExpression' &&
        node.callee.object?.name === 'axios'
      ) return true;
    }
  }

  // axios alias usage
  if (
    node.type === 'CallExpression' &&
    node.callee?.type === 'MemberExpression'
  ) {
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' && axiosAliases.has(obj.name)) {
      return true;
    }
  }

  // dynamic import
  if (node.type === 'ImportExpression') {
    return true;
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

  // detect axios import aliases
  const axiosAliases = new Set();
  estraverse.traverse(ast, {
    enter(node) {
      if (
        node.type === 'ImportDeclaration' &&
        node.source.value === 'axios'
      ) {
        for (const spec of node.specifiers) {
          axiosAliases.add(spec.local.name);
        }
      }
    }
  });

  const findings = [];
  estraverse.traverse(ast, {
    enter(node) {
      if (isSuspiciousNode(node, axiosAliases)) {
        findings.push({
          line: node.loc.start.line,
          snippet: code.split('\n')[node.loc.start.line - 1].trim()
        });
      }
    }
  });

  return findings;
}

// main
const resultsByFile = {};
let totalFindings = 0;

glob(pattern, { nodir: true }, (err, files) => {
  if (err) throw err;
  if (!files.length) {
    console.error(chalk.red(`❌ Tidak ada file yang cocok dengan pattern: ${pattern}`));
    process.exit(1);
  }

  files.forEach(file => {
    const absolute = path.resolve(file);
    const findings = scanFile(absolute);
    if (findings.length) {
      resultsByFile[file] = findings;
      totalFindings += findings.length;
    }
  });

  if (opts.json) {
    console.log(JSON.stringify({
      summary: { totalFiles: files.length, filesWithFindings: Object.keys(resultsByFile).length, totalFindings },
      details: resultsByFile
    }, null, 2));
  } else {
    Object.entries(resultsByFile).forEach(([file, findings]) => {
      console.log(chalk.blue.bold(`\n📄 ${file} (temuan: ${findings.length})`));
      findings.forEach(f => {
        console.log(chalk.yellow(`  [baris ${f.line}]`), chalk.gray(f.snippet));
      });
    });
    console.log(chalk.green.bold(`\n✅ Selesai. Total file: ${files.length}, file dengan temuan: ${Object.keys(resultsByFile).length}, total temuan: ${totalFindings}`));
  }
});
