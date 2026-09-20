// Prove Sealed Release end to end on GenLayer Asimov.
//
//   AT=0x... PADV=<padv keystore password> node scripts/prove.mjs
//
// Two seals against two real evidence pages in this repo:
//   - one that says a security advisory is published  -> check MET   -> opens
//   - one that says it is still embargoed             -> check NOT_MET -> stays sealed
// Plus the two refusals that matter: a wrong secret does not open a releasable
// record, and reveal on a record that is not releasable does nothing.
//
// It polls the record rather than waiting for FINALIZED, because Asimov can take
// a while to finalize a round and the state is the real proof anyway.
import { Wallet } from 'ethers';
import { createClient, createAccount } from 'genlayer-js';
import { testnetAsimov } from 'genlayer-js/chains';
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import url from 'url';

const AT = process.env.AT;
const PASS = process.env.PADV || '';
if (!AT || !PASS) { console.error('set AT and PADV'); process.exit(1); }

const ROOT = path.join(path.dirname(url.fileURLToPath(import.meta.url)), '..');
const caller = await Wallet.fromEncryptedJson(
  fs.readFileSync(path.join(os.homedir(), '.genlayer', 'keystores', 'padv.json'), 'utf8'), PASS);
const as = createClient({ chain: testnetAsimov, account: createAccount(caller.privateKey) });
const anybody = createClient({ chain: testnetAsimov });

const RAW = 'https://raw.githubusercontent.com/JspIIV/sealedrelease/master/docs/';
const MET_URL = RAW + 'advisory-2026-001-published.txt';
const EMBARGO_URL = RAW + 'advisory-2026-002-embargoed.txt';
const CONDITION = 'the page states that the security advisory has been published';
const SECRET0 = 'vault key: 8842-QORItaz-open-on-disclosure';
const SECRET1 = 'this one must never open, its condition is not met';
const sha = s => createHash('sha256').update(s, 'utf8').digest('hex');

const out = [];
const say = l => { console.log(l); out.push(l); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const transient = e => /-32005|-32006|-32029|-32603|at capacity|rate limit|gas rate|reverted.*consensus|consensus.*reverted|backpressure|fetch failed|timeout|502|503|429|ECONNRESET/i
  .test(String(e?.details || e?.shortMessage || e?.message || e));

const read = async (fn, args = []) => JSON.parse(await anybody.readContract({ address: AT, functionName: fn, args }));
async function write(fn, args) {
  for (let a = 1; ; a++) {
    try { return await as.writeContract({ address: AT, functionName: fn, args, value: 0n }); }
    catch (e) { if (!transient(e) || a >= 8) throw e; say(`  (${fn} transient, wait ${8 * a}s)`); await sleep(8000 * a); }
  }
}
async function pollGet(id, done, label) {
  for (let i = 0; i < 40; i++) {
    await sleep(12000);
    let r; try { r = await read('get', [id]); } catch { continue; }
    if (done(r)) { say(`  ${label} (${(i + 1) * 12}s)`); return r; }
  }
  throw new Error('timed out polling ' + label);
}

say('Sealed Release, proven on GenLayer Asimov');
say('  contract ' + AT);
say('');

// --- seal two records ---
const before = (await read('size')).total;
await write('seal', [sha(SECRET0), CONDITION, MET_URL]);
await pollGet('0', r => r.exists !== false && r.status, 'sealed #0 against the published page');
await write('seal', [sha(SECRET1), CONDITION, EMBARGO_URL]);
await pollGet('1', r => r.exists !== false && r.status, 'sealed #1 against the embargoed page');
say('');

// --- check #0: should be MET and become releasable ---
say('checking #0 (published advisory)...');
await write('check', ['0']);
const c0 = await pollGet('0', r => Number(r.checks) >= 1, 'checked #0');
say('  decision ' + c0.decision + ', status ' + c0.status);
say('  reason: ' + (c0.reason || '(none)'));
say('');

// --- a wrong secret must not open a releasable record ---
say('trying #0 with a WRONG secret...');
await write('reveal', ['0', 'not the secret']);
await sleep(6000);
const w0 = await read('get', ['0']);
say('  status after wrong secret: ' + w0.status);

// --- the matching secret opens it ---
say('revealing #0 with the correct secret...');
await write('reveal', ['0', SECRET0]);
const r0 = await pollGet('0', r => r.status === 'REVEALED', 'revealed #0');
const shown = await read('revealed', ['0']);
say('  revealed secret: ' + shown.secret);
say('');

// --- check #1: should be NOT_MET and stay sealed ---
say('checking #1 (embargoed advisory)...');
await write('check', ['1']);
const c1 = await pollGet('1', r => Number(r.checks) >= 1, 'checked #1');
say('  decision ' + c1.decision + ', status ' + c1.status);
say('  reason: ' + (c1.reason || '(none)'));
say('');

// --- reveal on a record that is not releasable does nothing ---
say('trying to reveal #1 while it is still sealed...');
await write('reveal', ['1', SECRET1]);
await sleep(6000);
const r1 = await read('get', ['1']);
say('  status of #1 after reveal attempt: ' + r1.status);
say('');

const size = await read('size');
say('register: ' + JSON.stringify(size));

const checks = [
  ['two records were sealed', before === 0 && size.total === 2],
  ['checking the published page returns MET', c0.decision === 'MET'],
  ['and that record becomes releasable', c0.status === 'RELEASABLE'],
  ['a wrong secret does not open a releasable record', w0.status === 'RELEASABLE'],
  ['the matching secret opens it', r0.status === 'REVEALED'],
  ['and the opened secret is readable', shown.revealed === true && shown.secret.length > 0],
  ['checking the embargoed page returns NOT_MET', c1.decision === 'NOT_MET'],
  ['and that record stays sealed', c1.status === 'SEALED'],
  ['reveal on a not-releasable record does nothing', r1.status === 'SEALED'],
  ['the register counts one revealed and one sealed', size.revealed === 1 && size.sealed === 1],
];
say('');
for (const [label, ok] of checks) say((ok ? '  ok   ' : ' FAIL  ') + label);
const failed = checks.filter(([, ok]) => !ok);
say('');
say(failed.length ? `${failed.length} of ${checks.length} checks failed` : `${checks.length} checks. It opened only what its condition allowed.`);

fs.mkdirSync(path.join(ROOT, 'results'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'results', 'proved.json'), JSON.stringify({
  proved_at: new Date().toISOString(), network: 'genlayer testnet asimov', contract: AT,
  condition: CONDITION, met_url: MET_URL, embargo_url: EMBARGO_URL,
  seal0: r0, seal1: r1, size, checks: checks.map(([label, ok]) => ({ label, ok })), transcript: out,
}, null, 2));
say('Written to results/proved.json');
process.exit(failed.length ? 1 : 0);
