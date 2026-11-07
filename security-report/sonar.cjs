const fs = require('node:fs');

async function evaluate({ core, host, token, taskFile, fetchImpl = fetch, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), attempts = 60 }) {
  if (!token) throw new Error('Missing SONAR_TOKEN');
  const base = new URL(host);
  if (base.protocol !== 'https:' || base.username || base.password) throw new Error('SONAR_HOST_URL must be HTTPS without embedded credentials');
  const properties = Object.fromEntries(fs.readFileSync(taskFile, 'utf8').split(/\r?\n/).filter(line => line.includes('=')).map(line => {
    const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)];
  }));
  if (!properties.ceTaskId) throw new Error('Missing SonarQube compute task ID');
  // Only the configured server receives the token, never a URL from an artifact.
  async function get(endpoint, params) {
    const url = new URL(`${host.replace(/\/$/, '')}/api/${endpoint}`);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const response = await fetchImpl(url, { headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`SonarQube API ${endpoint}: HTTP ${response.status}`);
    return response.json();
  }
  let analysisId;
  for (let count = 0; count < attempts; count++) {
    const { task } = await get('ce/task', { id: properties.ceTaskId });
    if (task?.status === 'SUCCESS' && task.analysisId) { analysisId = task.analysisId; break; }
    if (!['PENDING', 'IN_PROGRESS'].includes(task?.status)) throw new Error(`SonarQube compute task did not succeed: ${task?.status}`);
    if (count + 1 < attempts) await sleep(10000);
  }
  if (!analysisId) throw new Error('SonarQube compute task timed out');
  const data = await get('qualitygates/project_status', { analysisId });
  if (!data.projectStatus?.status) throw new Error('Missing Quality Gate result');
  fs.writeFileSync('sonar-quality-gate.json', JSON.stringify(data, null, 2));
  const gate = data.projectStatus;
  core.setOutput('gate', gate.status);
  const cell = value => String(value ?? '-').replace(/[<>&|\r\n]/g, ' ');
  await core.summary.addHeading('SonarQube · Quality Gate').addRaw(`Status: ${cell(gate.status)}\n`).addTable([
    ['Metric', 'Observed', 'Threshold', 'Status'],
    ...(gate.conditions || []).map(c => [c.metricKey, c.actualValue, c.errorThreshold, c.status].map(cell))
  ]).addRaw('\nIncludes configured security, reliability and maintainability conditions; hotspots require human review.\n').write();
  if (gate.status !== 'OK') core.setFailed(`SonarQube Quality Gate: ${gate.status}`);
}
module.exports = { evaluate };
