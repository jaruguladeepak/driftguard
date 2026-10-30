import fs from "node:fs";
import path from "node:path";
import { parseConfig, detectDrift } from "./core/detector";
import { evaluateFindings, shouldBlock } from "./core/policies";
import {
  generateReport,
  formatTerminalReport,
  generateMarkdownReport,
} from "./core/reporter";

function parseArgs(): { expected: string; actual: string } {
  const args = process.argv.slice(2);
  let expected = "config/expected.yaml";
  let actual = "config/actual.yaml";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--expected" && i + 1 < args.length) {
      expected = args[++i];
    } else if (args[i] === "--actual" && i + 1 < args.length) {
      actual = args[++i];
    }
  }

  return { expected, actual };
}

function main() {
  const { expected: expectedPath, actual: actualPath } = parseArgs();

  try {
    if (!fs.existsSync(expectedPath)) {
      throw new Error(`File not found: ${expectedPath}`);
    }
    if (!fs.existsSync(actualPath)) {
      throw new Error(`File not found: ${actualPath}`);
    }

    const expectedContent = fs.readFileSync(expectedPath, "utf-8");
    const actualContent = fs.readFileSync(actualPath, "utf-8");

    const expected = parseConfig(expectedContent, expectedPath);
    const actual = parseConfig(actualContent, actualPath);

    const differences = detectDrift(expected, actual);
    const findings = evaluateFindings(differences);
    const report = generateReport(expectedPath, actualPath, findings);

    console.log(formatTerminalReport(report));

    const reportsDir = path.resolve("reports");
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const jsonPath = path.join(reportsDir, "drift-report.json");
    const mdPath = path.join(reportsDir, "drift-report.md");

    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    fs.writeFileSync(mdPath, generateMarkdownReport(report), "utf-8");

    console.log(`\nJSON report: ${jsonPath}`);
    console.log(`Markdown report: ${mdPath}`);

    if (shouldBlock(findings)) {
      console.log("\nRESULT: Critical configuration drift detected.");
      process.exit(1);
    }

    console.log("\nRESULT: No critical configuration drift detected.");
    process.exit(0);
  } catch (error: any) {
    console.error(`Configuration error: ${error.message}`);
    process.exit(2);
  }
}

main();

