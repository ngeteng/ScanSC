#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const glob = require('glob');
const espree = require('espree');
const estraverse = require('estraverse');
const chalkImport = require('chalk');
const chalk = chalkImport.default ?? chalkImport;
const { Command } = require('commander');
const os = require('os');

// Node 18+ has global fetch; if unavailable, instruct to install node-fetch
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

const suspicious = [
  // ... same as before
];
const externalServices = [
  // ... same as before
];

function isSuspiciousNode(node, axiosAliases) {
  // ... same as before, with optional chaining guards
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
      const res = await fetch(opts.url);
      const code = await res.text();
      const findings = scanCode(code);
      resultsByFile[opts.url] = findings;
      totalFindings = findings.length;
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
      outputResults(files.length);
    });
    return;
  }

  outputResults(opts.url ? 1 : 0);

  function outputResults(totalFiles) {
    if (opts.json) {
      console.log(JSON.stringify({ summary: { totalFiles, filesWithFindings: Object.keys(resultsByFile).length, totalFindings }, details: resultsByFile }, null, 2));
    } else {
      Object.entries(resultsByFile).forEach(([key, findings]) => {
        console.log(chalk.blue(`\n📄 ${key} (temuan: ${findings.length})`));
        findings.forEach(f => console.log(chalk.yellow(`  [baris ${f.line}]`), chalk.gray(f.snippet)));
      });
      console.log(chalk.green(`\n✅ Selesai. Total file: ${totalFiles}, file dengan temuan: ${Object.keys(resultsByFile).length}, total temuan: ${totalFindings}`));
    }
  }
})();
