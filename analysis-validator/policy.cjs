module.exports = function policy(context, technology, language = '') {
  if (!['maven', 'node'].includes(technology)) throw new Error('Unsupported technology');
  const selected = language || (technology === 'maven' ? 'java' : 'typescript');
  const supported = { maven: ['java'], node: ['javascript', 'typescript'] };
  if (!supported[technology].includes(selected)) throw new Error('Unsupported technology/language combination');
  const analysis = { language: selected, codeql_language: technology === 'maven' ? 'java-kotlin' : 'javascript-typescript', codeql_build_mode: technology === 'maven' ? 'manual' : 'none' };
  const pr = context.payload?.pull_request;
  if (context.eventName === 'pull_request') {
    if (!pr || !['develop', 'main'].includes(pr.base.ref)) throw new Error('Unsupported PR target');
    if (pr.base.ref === 'main' && (pr.head.ref !== 'develop' || pr.head.repo.full_name !== context.payload.repository.full_name)) {
      throw new Error('Production changes must originate from develop in this repository');
    }
    return { ...analysis, blocking: pr.base.ref === 'main', sonar: true, dependency_review: true };
  }
  if (!['push', 'workflow_dispatch'].includes(context.eventName)) throw new Error('Unsupported event');
  if (!['refs/heads/main', 'refs/heads/develop'].includes(context.ref)) throw new Error('Unsupported branch');
  return { ...analysis, blocking: context.ref === 'refs/heads/main', sonar: true, dependency_review: false };
};
