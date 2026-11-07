const fs = require('node:fs');
const marker = '<!-- retail-security-review -->';
const stages = [
  ['sonar_analysis', 'SonarQube · SAST and code quality'],
  ['sonar_gate', 'SonarQube · Quality Gate'],
  ['ghas_sast', 'GHAS · SAST / CodeQL'],
  ['ghas_sca', 'GHAS · SCA / Dependency Review']
];
function decision(needs) {
  const valid = needs.validation?.result === 'success';
  const blocking = needs.validation?.outputs?.blocking !== 'false';
  const failed = stages.filter(([id]) => needs[id]?.result !== 'success' || needs[id]?.outputs?.outcome !== 'success').map(([id]) => id);
  const buildTest = needs.build_test?.result;
  const buildTestPassed = buildTest === undefined || buildTest === 'success';
  return { valid, blocking, failed, buildTest, buildTestPassed,
    pass: valid && buildTestPassed && (!blocking || failed.length === 0) };
}
async function publish({ github, context, core, needs, technology, language, host }) {
  const result = decision(needs);
  const run = `${context.serverUrl || 'https://github.com'}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  const security = `${context.serverUrl || 'https://github.com'}/${context.repo.owner}/${context.repo.repo}/security/code-scanning`;
  const cell = value => String(value ?? 'unavailable').replace(/[<>&|`\r\n]/g, ' ');
  const label = !result.valid ? '⛔ Invalid analysis context' : !result.buildTestPassed ? '⛔ Build or unit tests failed' : !result.pass ? '⛔ Promotion blocked' : result.failed.length ? '⚠️ Advisory findings or incomplete analyses' : '✅ Security checks passed';
  const rows = [`| Build and unit tests | ${result.buildTestPassed ? '✅ success' : `⛔ ${cell(result.buildTest || 'missing')}`} | Required for PRs to develop and main |`, ...stages.map(([id, title]) => {
    const job = needs[id];
    const state = job?.outputs?.outcome || job?.result || 'missing';
    let details = 'See job logs and report artifacts';
    if (id === 'ghas_sast' && job?.outputs?.high !== undefined && job.outputs.high !== '') details = `High: ${job.outputs.high}; critical: ${job.outputs.critical}`;
    if (id === 'sonar_gate' && job?.outputs?.gate) details = `Gate: ${job.outputs.gate}`;
    if (id === 'ghas_sca' && job?.outputs?.vulnerabilities !== undefined && job.outputs.vulnerabilities !== '') details = `Vulnerable dependency changes: ${job.outputs.vulnerabilities}`;
    return `| ${title} | ${state === 'success' ? '✅' : '⚠️'} ${cell(state)} | ${cell(details)} |`;
  })];
  let sonarLink = '';
  try {
    const url = new URL(`${host.replace(/\/$/, '')}/dashboard`);
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Invalid host');
    url.searchParams.set('id', `${context.repo.owner}_${context.repo.repo}`);
    url.searchParams.set('pullRequest', String(context.payload.pull_request.number));
    sonarLink = ` · [SonarQube report](<${url.href}>)`;
  } catch { /* Configuration errors remain visible in the analysis jobs. */ }
  const body = `${marker}\n## 🛡️ Retail · Pull Request Security Review\n\n**${label}**\n\n` +
    `Security policy: **${result.blocking ? 'mandatory · main' : 'advisory · develop'}** · Build/tests: **required** · Stack: **${cell(technology)} / ${cell(language)}**\n\n` +
    `| Control | Execution | Details |\n|---|---|---|\n${rows.join('\n')}\n\n` +
    `[Actions run and artifacts](${run}) · [Code scanning alerts](${security})${sonarLink}\n\n` +
    '<details><summary>Scope and interpretation</summary>\n\n' +
    '- CodeQL analyzes the selected language; high/critical findings in the scanned source fail its gate (including existing findings).\n' +
    '- Dependency Review evaluates dependency changes and high/critical known vulnerabilities, not a complete inventory scan.\n' +
    '- SonarQube evaluates new-code conditions configured in its Quality Gate. Security hotspots need human review.\n' +
    '- Failed, missing, cancelled or skipped mandatory analyses never count as passed.\n' +
    '- Build and unit tests are required for every PR. GHAS and SonarQube findings are advisory for develop and mandatory for main.\n\n</details>\n\n' +
    `Analyzed PR head: \`${cell(context.payload.pull_request?.head?.sha)}\` · Run attempt: ${cell(process.env.GITHUB_RUN_ATTEMPT || '1')}\n`;
  fs.writeFileSync('pr-security-report.md', body);
  await core.summary.addRaw(body).write();
  const pr = context.payload.pull_request;
  // Do not use a privileged PAT or pull_request_target for untrusted code.
  if (context.eventName === 'pull_request' && pr?.head?.repo?.full_name === `${context.repo.owner}/${context.repo.repo}`) {
    try {
      const { data: latest } = await github.rest.pulls.get({ ...context.repo, pull_number: pr.number });
      if (latest.head.sha !== pr.head.sha) {
        core.notice('A newer PR commit exists; the outdated report will not replace its comment.');
      } else {
        const comments = await github.paginate(github.rest.issues.listComments, { ...context.repo, issue_number: pr.number, per_page: 100 });
        const previous = comments.find(c => c.user?.login === 'github-actions[bot]' && c.body?.startsWith(marker));
        if (previous) await github.rest.issues.updateComment({ ...context.repo, comment_id: previous.id, body });
        else await github.rest.issues.createComment({ ...context.repo, issue_number: pr.number, body });
      }
    } catch (error) { core.warning(`PR comment could not be updated (HTTP ${error.status || 'unknown'}). Report remains in Actions.`); }
  } else core.notice('Fork PR: report published in Actions only; no elevated token is used.');
  if (!result.pass) core.setFailed('Required PR build, unit tests or security policy did not pass. See the report above.');
}
module.exports = { decision, publish };
