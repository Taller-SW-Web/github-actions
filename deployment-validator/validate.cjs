module.exports = async function validate({ github, context, rollback, tag, triggeringActor, report = () => {} }) {
  if (!['push', 'workflow_dispatch'].includes(context.eventName)) {
    throw new Error('Production workflows require push or workflow_dispatch');
  }
  if (rollback) {
    if (context.eventName !== 'workflow_dispatch' || !tag ||
        !['refs/heads/main', `refs/tags/${tag}`].includes(context.ref)) {
      throw new Error('For rollback, select a production tag in Use workflow from and enable the rollback checkbox');
    }
  } else if (context.ref !== 'refs/heads/main') {
    throw new Error('Normal production deployments must run from main');
  }
  const repo = context.repo;
  let denied = false;
  for (const username of new Set([context.actor, triggeringActor || context.actor])) {
    let state;
    let reason;
    try {
      const { data } = await github.rest.teams.getMembershipForUserInOrg({
        org: repo.owner, team_slug: 'retail-operator', username
      });
      state = data.state;
      reason = state === 'active' ? 'Miembro activo' : 'La membresia no esta activa';
    } catch (error) {
      state = 'unverified';
      reason = error.status === 404
        ? 'No pertenece al equipo o el equipo no es visible para el token'
        : `No se pudo verificar la membresia (HTTP ${error.status || 'no disponible'})`;
    }
    report({ username, team: `${repo.owner}/retail-operator`, state, reason });
    if (state !== 'active') denied = true;
  }
  if (denied) throw new Error('Despliegue bloqueado: todos los actores deben ser miembros activos del equipo retail-operator.');
  if (!rollback) {
    if (tag) throw new Error('A release tag requires the rollback checkbox');
    return context.sha;
  }
  const match = /^production-(\d+)-(\d+)$/.exec(tag);
  if (!match) throw new Error('Select a production-<run_id>-<attempt> release tag');
  const { data: ref } = await github.rest.git.getRef({ ...repo, ref: `tags/${tag}` });
  if (ref.object.type !== 'tag') throw new Error('Release must be an annotated tag');
  const { data: release } = await github.rest.git.getTag({ ...repo, tag_sha: ref.object.sha });
  if (release.object.type !== 'commit') throw new Error('Release must point directly to a commit');
  const { data: run } = await github.rest.actions.getWorkflowRunAttempt({
    ...repo, run_id: Number(match[1]), attempt_number: Number(match[2])
  });
  if (run.conclusion !== 'success' || run.head_branch !== 'main' ||
      run.path !== '.github/workflows/workflow-main.yml' ||
      !['push', 'workflow_dispatch'].includes(run.event) || run.head_sha !== release.object.sha) {
    throw new Error('Tag does not identify a successful production deployment');
  }
  return release.object.sha;
};
