const validate = require('./validate.cjs');

module.exports = async function execute({ github, context, core, rollback, tag, triggeringActor }) {
  const rows = [];
  let failure;
  let sha;
  try {
    sha = await validate({ github, context, rollback, tag, triggeringActor, report: row => rows.push(row) });
    core.setOutput('source_sha', sha);
  } catch (error) {
    failure = error.message;
    core.setFailed(failure);
  } finally {
    await core.summary.addHeading('Validacion de autorizacion por equipo')
      .addTable([
        ['Usuario GitHub', 'Equipo requerido', 'Estado', 'Detalle'],
        ...rows.map(row => [row.username, row.team, row.state, row.reason])
      ])
      .addRaw(failure ? `\nResultado: BLOQUEADO. ${failure}\n` : `\nResultado: AUTORIZADO. Commit: ${sha}\n`)
      .write();
  }
};
