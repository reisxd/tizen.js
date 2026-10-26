'use strict';

/**
 * Network install/launch for Tizen TVs without Tizen Studio.
 *
 * Reverse-engineered on retail Tizen (UE49RU7372, Tizen 5.0):
 * - Generic `sdb shell` is refused by the TV (sdbd advertises
 *   `intershell_support:disabled`; the sdb CLI sends bare `shell:<cmd>`
 *   which always yields CLSE).
 * - The `:0` exec form for an allowlisted command set IS honored:
 *     `shell:0 vd_appinstall <pkg_id> <remote.wgt>` -> progress stream
 *     `shell:0 execute <app_id>`                     -> launch
 * - The local sdb server (127.0.0.1:26099) speaks the length-prefixed
 *   smart protocol (`host:transport:<serial>`), so no Studio needed —
 *   only the `sdb` binary for device listing and file push.
 */

const net = require('net');
const { spawnSync } = require('child_process');

const REMOTE_DIR = '/home/owner/share/tmp/sdk_tools';
const SERVER_HOST = '127.0.0.1';
const SERVER_PORT = 26099;

function frame(payload) {
    const body = Buffer.from(payload, 'utf8');
    const head = Buffer.from(body.length.toString(16).padStart(4, '0'), 'ascii');
    return Buffer.concat([head, body]);
}

function listDevices(sdbBin = 'sdb') {
    const r = spawnSync(sdbBin, ['devices'], { encoding: 'utf8' });
    const devs = [];
    for (const line of (r.stdout || '').split('\n')) {
        const m = line.trim().match(/^(\S+)\s+(device|offline|unauthorized|unknown)\b/);
        if (m && m[1] !== 'List') devs.push({ serial: m[1], status: m[2] });
    }
    return devs;
}

function resolveSerial(serial, sdbBin) {
    if (serial) return serial;
    const devs = listDevices(sdbBin).filter((d) => d.status === 'device');
    if (!devs.length) throw new Error('No connected SDB device found.');
    return devs[0].serial;
}

/**
 * Open a persistent exec stream: transport switch + `shell:0 <command>`.
 * Resolves with the full streamed output when the daemon closes the stream.
 */
async function execStream(command, { serial, sdbBin = 'sdb', onOutput = () => {}, timeoutMs = 60000 }) {
    serial = resolveSerial(serial, sdbBin);
    const sock = net.createConnection({ host: SERVER_HOST, port: SERVER_PORT });
    await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('transport connect timed out')), 15000);
        sock.once('connect', () => { clearTimeout(t); resolve(); });
        sock.once('error', (e) => { clearTimeout(t); reject(e); });
    });
    const status = await new Promise((resolve, reject) => {
        let acc = Buffer.alloc(0);
        const t = setTimeout(() => reject(new Error('transport handshake timed out')), 15000);
        const onData = (c) => {
            acc = Buffer.concat([acc, c]);
            if (acc.length >= 4) {
                clearTimeout(t);
                sock.removeListener('data', onData);
                resolve({ status: acc.slice(0, 4).toString(), surplus: acc.slice(4) });
            }
        };
        sock.on('data', onData);
        sock.once('error', (e) => { clearTimeout(t); reject(e); });
        sock.write(frame(`host:transport:${serial}`));
    });
    if (status.status !== 'OKAY') {
        sock.destroy();
        throw new Error(`transport rejected: ${status.status}`);
    }
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { sock.destroy(); reject(new Error(`command timed out after ${timeoutMs}ms: ${command.slice(0, 60)}`)); }, timeoutMs);
        let out = '';
        let first = true;
        const feed = (chunk) => {
            let text = chunk.toString('utf8');
            // Strip a leading transport OKAY echoed into the stream once.
            if (first) {
                first = false;
                text = text.replace(/^OKAY/, '');
            }
            out += text;
            onOutput(text);
        };
        if (status.surplus && status.surplus.length) feed(status.surplus);
        sock.on('data', feed);
        sock.on('close', () => { clearTimeout(timer); resolve(out); });
        sock.on('error', (e) => { clearTimeout(timer); reject(e); });
        sock.write(frame(command));
    });
}

async function installWgt({ wgtPath, pkgId, serial, sdbBin = 'sdb', onOutput = () => {}, timeoutMs = 120000 }) {
    const fileName = wgtPath.split('/').pop();
    const remotePath = `${REMOTE_DIR}/${fileName}`;
    serial = resolveSerial(serial, sdbBin);

    // 1. Push (file channel is unrestricted).
    const push = spawnSync(sdbBin, ['-s', serial, 'push', wgtPath, remotePath], { encoding: 'utf8' });
    if (push.status !== 0) {
        throw new Error(`sdb push failed: ${(push.stderr || push.stdout || '').trim()}`);
    }

    // 2-3. Installer command over the exec stream.
    const output = await execStream(`shell:0 vd_appinstall ${pkgId} ${remotePath}`, { serial, sdbBin, onOutput, timeoutMs });

    // A failed install is reported with a sentence that contains the word "Success":
    //   app_id[x] install failed[118, 0], reason: Success :
    // so "reason: Success" is part of the failure line and must never be read as a verdict.
    // Only `install completed` marks success; `install failed[<code>, <detail>]` is failure.
    const failure = /install failed\[(\d+),\s*(-?\d+)\](?:,\s*reason:\s*([^:\n]*))?/i.exec(output);
    const ok = !failure && /install completed/i.test(output);

    return {
        success: ok,
        output,
        packageId: pkgId,
        remotePath,
        ...(failure
            ? {
                errorCode: Number(failure[1]),
                errorDetail: Number(failure[2]),
                errorReason: (failure[3] || '').trim()
            }
            : {})
    };
}

async function launchApp({ appId, serial, sdbBin = 'sdb', onOutput = () => {}, timeoutMs = 30000 }) {
    const output = await execStream(`shell:0 execute ${appId}`, { serial, sdbBin, onOutput, timeoutMs });
    const ok = /successfully launched|pid\s*=\s*\d+/i.test(output);
    return { success: ok, output, appId };
}

module.exports = { installWgt, launchApp, execStream, listDevices, REMOTE_DIR };
