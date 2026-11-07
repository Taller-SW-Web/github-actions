const fs = require('node:fs');
const path = require('node:path');

function summarize(documents) {
  if (!documents.length) throw new Error('No SARIF report was generated');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, other: 0 };
  for (const document of documents) {
    if (!Array.isArray(document.runs) || !document.runs.length) throw new Error('Invalid SARIF report');
    for (const run of document.runs) {
      if (!Array.isArray(run.results)) throw new Error('SARIF results are missing');
      const rules = run.tool?.driver?.rules || [];
      for (const result of run.results) {
        const rule = rules.find(item => item.id === result.ruleId) || rules[result.ruleIndex];
        const raw = rule?.properties?.['security-severity'];
        const score = raw === undefined ? NaN : Number(raw);
        const level = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score >= 0 ? 'low' : 'other';
        counts[level]++;
      }
    }
  }
  return { counts, blocked: counts.critical + counts.high > 0 };
}

async function run(core, directory) {
  const files = fs.readdirSync(directory).filter(file => file.endsWith('.sarif'));
  const result = summarize(files.map(file => JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8'))));
  fs.writeFileSync(path.join(directory, 'security-summary.json'), JSON.stringify(result, null, 2));
  core.setOutput('high', result.counts.high);
  core.setOutput('critical', result.counts.critical);
  await core.summary.addHeading('GHAS SAST · CodeQL').addTable([
    ['Severity', 'Findings'], ...Object.entries(result.counts).map(([key, value]) => [key, String(value)])
  ]).addRaw('\nPolicy: fail for high/critical findings in the analyzed source. Full SARIF is available in artifacts.\n').write();
  if (result.blocked) core.setFailed('CodeQL detected high or critical security findings');
}
module.exports = { summarize, run };
