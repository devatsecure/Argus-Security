#!/usr/bin/env node
/**
 * Sample CLI Tool - NOT a web application
 * This is a command-line tool that outputs to terminal (console.log)
 * XSS findings in console.log should be FALSE POSITIVES for CLI tools
 */

const { program } = require('commander');
const chalk = require('chalk');

program
  .name('test-cli')
  .description('A sample CLI tool for testing')
  .version('1.0.0');

program
  .command('run <script>')
  .description('Run a script with user input')
  .action((script) => {
    // POTENTIAL FALSE POSITIVE: This is console.log in a CLI tool, NOT browser XSS
    // Semgrep might flag this as XSS (innerHTML-like pattern)
    // But this outputs to TERMINAL, not browser DOM
    console.log(`Run script: ${script}`);
    console.log(chalk.green(`Executing: ${script}`));
  });

program
  .command('display <message>')
  .description('Display a message to terminal')
  .action((message) => {
    // Another potential false positive - terminal output, not DOM
    const formattedMessage = `Message: ${message}`;
    console.log(formattedMessage);
  });

program
  .command('log <data>')
  .option('-f, --format <type>', 'output format', 'text')
  .action((data, options) => {
    // CLI logging - should NOT be flagged as XSS
    if (options.format === 'json') {
      console.log(JSON.stringify({ data }));
    } else {
      console.log(`[LOG] ${data}`);
    }
  });

program.parse(process.argv);
