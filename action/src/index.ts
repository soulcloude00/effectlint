import * as core from '@actions/core';
import * as exec from '@actions/exec';

export async function run(): Promise<void> {
  try {
    const input = core.getInput('input', { required: true });
    const baseline = core.getInput('baseline', { required: true });
    const format = core.getInput('format') || 'sarif';
    const output = core.getInput('output') || 'effectlint.sarif';
    let stdout = '';
    await exec.exec('effectlint', [input, '--baseline', baseline, '--format', format], {
      listeners: { stdout: (data) => { stdout += data.toString(); } }
    });
    await import('node:fs/promises').then((fs) => fs.writeFile(output, stdout));
    const parsed = JSON.parse(stdout);
    const count = format === 'sarif' ? (parsed.runs?.[0]?.results?.length ?? 0) : (parsed.capabilities?.length ?? 0);
    core.setOutput('finding-count', count);
    core.setOutput('output', output);
    if (count > 0) core.warning(`effectlint found ${count} new authority change(s)`);
  } catch (error) { core.setFailed(error instanceof Error ? error.message : String(error)); }
}
if (process.env.NODE_ENV !== 'test') void run();
