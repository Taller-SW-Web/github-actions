const { test } = require('node:test');
const assert = require('node:assert/strict');
const policy = require('../analysis-validator/policy.cjs');
const validate = require('../deployment-validator/validate.cjs');
const execute = require('../deployment-validator/execute.cjs');
const repo = { owner: 'retail', repo: 'backend' };
const context = { repo, eventName: 'workflow_dispatch', ref: 'refs/heads/main', actor: 'operator', sha: 'current' };
function mock(overrides = {}) {
  const calls = [];
  const github = { rest: {
    teams: { getMembershipForUserInOrg: async ({ org, team_slug, username }) => {
      assert.equal(org, repo.owner);
      assert.equal(team_slug, 'retail-operator');
      calls.push(username);
      if (overrides.apiError) throw Object.assign(new Error('API unavailable'), { status: overrides.apiError });
      return { data: { state: overrides.states?.[username] || 'active' } };
    } },
    git: {
      getRef: async () => ({ data: { object: { type: overrides.refType || 'tag', sha: 'tag-object' } } }),
      getTag: async () => ({ data: { object: { type: 'commit', sha: 'previous' } } })
    },
    actions: { getWorkflowRunAttempt: async () => ({ data: {
      conclusion: 'success', head_branch: 'main', path: '.github/workflows/workflow-main.yml',
      event: 'push', head_sha: 'previous', ...overrides.run
    } }) }
  } };
  return { github, calls };
}
function pr(base, head, fork = false) {
  return { eventName: 'pull_request', payload: { repository: { full_name: 'retail/backend' },
    pull_request: { base: { ref: base }, head: { ref: head, repo: { full_name: fork ? 'fork/backend' : 'retail/backend' } } }
  } };
}
test('feature to develop is advisory; develop to main is mandatory', () => {
  assert.equal(policy(pr('develop', 'feature/payment'), 'node').blocking, false);
  assert.equal(policy(pr('main', 'develop'), 'maven').blocking, true);
});
test('main rejects other source branches and fork impersonation', () => {
  assert.throws(() => policy(pr('main', 'feature/payment'), 'node'));
  assert.throws(() => policy(pr('main', 'develop', true), 'node'));
});
test('unsupported technologies and contexts fail closed', () => {
  assert.throws(() => policy(pr('develop', 'feature/x'), 'unknown'));
  assert.throws(() => policy({ eventName: 'push', ref: 'refs/heads/feature/x' }, 'node'));
  assert.throws(() => policy({ eventName: 'pull_request_target' }, 'node'));
});
test('main push is mandatory', () => {
  assert.equal(policy({ eventName: 'push', ref: 'refs/heads/main' }, 'node').blocking, true);
});
test('normal deployment requires team membership and uses the triggering SHA', async () => {
  const m = mock();
  assert.equal(await validate({ ...m, context, rollback: false, tag: '' }), 'current');
  assert.deepEqual(m.calls, ['operator']);
});
test('rollback resolves an authorized successful release and checks both actors', async () => {
  const m = mock();
  assert.equal(await validate({ ...m, context, rollback: true, tag: 'production-123-1', triggeringActor: 'second' }), 'previous');
  assert.deepEqual(m.calls, ['operator', 'second']);
});
for (const overrides of [
  { states: { operator: 'pending' } }, { states: { second: 'pending' } },
  { apiError: 404 }, { apiError: 403 }, { apiError: 500 },
  { refType: 'commit' }, { run: { conclusion: 'failure' } }, { run: { conclusion: null } },
  { run: { head_sha: 'wrong' } }, { run: { head_branch: 'develop' } },
  { run: { path: '.github/workflows/workflow-pr.yml' } }, { run: { event: 'pull_request' } }
]) test(`rollback denied: ${JSON.stringify(overrides)}`, async () => {
  await assert.rejects(validate({ ...mock(overrides), context, rollback: true, tag: 'production-123-1', triggeringActor: 'second' }));
});
for (const input of [
  { context: { ...context, ref: 'refs/heads/develop' } },
  { context: { ...context, eventName: 'push' } },
  { tag: 'main' }, { tag: '' }, { tag: '../production-123-1' },
  { rollback: false, tag: 'production-123-1' }
]) test(`invalid deployment input: ${JSON.stringify(input)}`, async () => {
  await assert.rejects(validate({ ...mock(), context, rollback: true, tag: 'production-123-1', ...input }));
});

for (const eventName of ['push', 'workflow_dispatch']) {
  test(`${eventName} normal deployment cannot bypass membership`, async () => {
    await assert.rejects(validate({ ...mock({ apiError: 404 }), context: { ...context, eventName }, rollback: false, tag: '' }), /bloqueado/);
  });
}

for (const denied of [false, true]) {
  test(`summary and outputs for ${denied ? 'denied' : 'authorized'} deployment`, async () => {
    const state = { outputs: {}, writes: 0, text: '' };
    const summary = {
      addHeading() { return this; },
      addTable(rows) { state.rows = rows; return this; },
      addRaw(text) { state.text += text; return this; },
      async write() { state.writes++; }
    };
    const core = { summary, setOutput: (k, v) => state.outputs[k] = v, setFailed: message => state.failure = message };
    await execute({ ...mock(denied ? { apiError: 404 } : {}), context, core, rollback: false, tag: '' });
    assert.equal(state.writes, 1);
    assert.equal(state.rows[1][0], 'operator');
    assert.equal(state.rows[1][1], 'retail/retail-operator');
    if (denied) {
      assert.match(state.failure, /bloqueado/);
      assert.match(state.text, /BLOQUEADO/);
      assert.match(state.rows[1][3], /No pertenece/);
      assert.deepEqual(state.outputs, {});
    } else {
      assert.equal(state.failure, undefined);
      assert.match(state.text, /AUTORIZADO/);
      assert.equal(state.outputs.source_sha, 'current');
    }
  });
}
