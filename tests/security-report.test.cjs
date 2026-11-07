const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const policy = require('../analysis-validator/policy.cjs');
const { summarize } = require('../security-report/sarif.cjs');
const { evaluate } = require('../security-report/sonar.cjs');
const { decision, publish } = require('../security-report/pr.cjs');

function coreMock() {
  const state = { outputs: {}, written: false, text: '', warnings: [] };
  const summary = {
    addHeading() { return this; }, addTable(rows) { state.rows = rows; return this; },
    addRaw(value) { state.text += value; return this; }, async write() { state.written = true; }
  };
  return { state, core: { summary, setOutput(k, v) { state.outputs[k] = v; }, setFailed(message) { state.failure = message; },
    warning(message) { state.warnings.push(message); }, notice() {} } };
}
function needs(blocking = true) {
  return Object.fromEntries([
    ['validation', { result: 'success', outputs: { blocking: String(blocking) } }],
    ...['sonar_analysis', 'sonar_gate', 'ghas_sast', 'ghas_sca'].map(id => [id, { result: 'success', outputs: { outcome: 'success' } }])
  ]);
}
test('technology and language resolve to the appropriate CodeQL extractor', () => {
  const ctx = { eventName: 'push', ref: 'refs/heads/main' };
  assert.equal(policy(ctx, 'maven', 'java').codeql_build_mode, 'manual');
  for (const language of ['javascript', 'typescript']) assert.equal(policy(ctx, 'node', language).codeql_language, 'javascript-typescript');
  assert.throws(() => policy(ctx, 'maven', 'typescript'));
  assert.throws(() => policy(ctx, 'node', 'java'));
  assert.throws(() => policy(ctx, 'node', 'python'));
});
test('SARIF high/critical gate counts findings instead of treating scanner success as clean', () => {
  const scores = [9.8, 7.5, 5, 2, undefined];
  const rules = scores.map((score, index) => ({ id: `rule${index}`, properties: score === undefined ? {} : { 'security-severity': String(score) } }));
  const document = { runs: [{ tool: { driver: { rules } }, results: rules.map(rule => ({ ruleId: rule.id })) }] };
  assert.deepEqual(summarize([document]), { blocked: true, counts: { critical: 1, high: 1, medium: 1, low: 1, other: 1 } });
  document.runs[0].results = [];
  assert.equal(summarize([document]).blocked, false);
});
test('missing or malformed SARIF cannot pass as zero vulnerabilities', () => {
  for (const reports of [[], [{}], [{ runs: [] }], [{ runs: [{}] }]]) assert.throws(() => summarize(reports));
});
test('main fails for missing, skipped or failed analyses; develop remains advisory', () => {
  assert.equal(decision(needs()).pass, true);
  for (const id of ['sonar_analysis', 'sonar_gate', 'ghas_sast', 'ghas_sca']) {
    for (const outcome of ['failure', 'skipped', 'cancelled', undefined]) {
      const mandatory = needs(); mandatory[id].outputs.outcome = outcome;
      assert.equal(decision(mandatory).pass, false);
      mandatory.validation.outputs.blocking = 'false';
      assert.equal(decision(mandatory).pass, true);
    }
  }
  const invalid = needs(false); invalid.validation.result = 'failure';
  assert.equal(decision(invalid).pass, false);
  const cancelled = needs(); cancelled.ghas_sast.result = 'cancelled';
  assert.equal(decision(cancelled).pass, false);
});

for (const gate of ['OK', 'ERROR', 'NONE']) test(`Sonar gate ${gate} is tied to the exact compute task analysis`, async t => {
  const { core, state } = coreMock();
  t.mock.method(fs, 'readFileSync', () => 'ceTaskId=task-123\nceTaskUrl=https://attacker.invalid/steal');
  t.mock.method(fs, 'writeFileSync', () => {});
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push(url);
    assert.equal(url.origin, 'https://sonar.example');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    return { ok: true, json: async () => url.pathname.endsWith('ce/task')
      ? { task: { status: 'SUCCESS', analysisId: 'exact-analysis' } }
      : { projectStatus: { status: gate, conditions: [{ metricKey: 'new_security_rating', status: gate, actualValue: '1' }] } } };
  };
  await evaluate({ core, host: 'https://sonar.example', token: 'test-token', taskFile: 'unused', fetchImpl });
  assert.equal(requests[1].searchParams.get('analysisId'), 'exact-analysis');
  assert.equal(state.outputs.gate, gate);
  assert.equal(Boolean(state.failure), gate !== 'OK');
  assert.equal(state.written, true);
});
test('Sonar API failure, pending timeout and compute failure never pass', async t => {
  t.mock.method(fs, 'readFileSync', () => 'ceTaskId=task-123');
  for (const response of [
    { ok: false, status: 403 },
    { ok: true, json: async () => ({ task: { status: 'PENDING' } }) },
    { ok: true, json: async () => ({ task: { status: 'FAILED' } }) }
  ]) await assert.rejects(evaluate({ core: coreMock().core, host: 'https://sonar.example', token: 'test', taskFile: 'unused', attempts: 1, fetchImpl: async () => response }));
});

function context(fork = false) {
  return { repo: { owner: 'Taller-SW-Web', repo: 'G4-Retail-backend' }, runId: 123,
    eventName: 'pull_request', payload: { pull_request: { number: 7, head: { sha: 'abc123', repo: { full_name: fork ? 'fork/backend' : 'Taller-SW-Web/G4-Retail-backend' } } } } };
}
for (const scenario of ['create', 'update', 'fork', 'stale', 'forbidden']) test(`PR report: ${scenario}`, async t => {
  const { core, state } = coreMock();
  t.mock.method(fs, 'writeFileSync', () => {});
  const calls = [];
  const github = { rest: {
    pulls: { get: async () => ({ data: { head: { sha: scenario === 'stale' ? 'newer' : 'abc123' } } }) },
    issues: { listComments() {}, createComment: async () => { calls.push('create'); if (scenario === 'forbidden') throw { status: 403 }; },
      updateComment: async () => calls.push('update') }
  }, paginate: async () => scenario === 'update' ? [{ id: 1, user: { login: 'github-actions[bot]' }, body: '<!-- retail-security-review --> old' }] : [] };
  const results = needs(); results.ghas_sast.outputs.outcome = 'failure';
  await publish({ github, context: context(scenario === 'fork'), core, needs: results, technology: 'maven', language: 'java', host: 'https://sonar.example' });
  assert.equal(state.written, true);
  assert.ok(state.failure, 'comment permissions must never weaken mandatory analysis gates');
  assert.match(state.text, /Promotion blocked/);
  assert.deepEqual(calls, scenario === 'stale' || scenario === 'fork' ? [] : [scenario === 'update' ? 'update' : 'create']);
});
