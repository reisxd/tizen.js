const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');
const forge = require('node-forge');

test('author PKCS#12 contains a private key matching the author certificate', () => {
    const home = mkdtempSync(join(tmpdir(), 'tizen-author-cert-'));
    try {
        // A disposable CA exercises the SDK certificate format without a download
        // or access to the developer's real certificate directory.
        const caKeys = forge.pki.rsa.generateKeyPair(1024);
        const ca = forge.pki.createCertificate();
        ca.publicKey = caKeys.publicKey;
        ca.serialNumber = '01';
        ca.validity.notBefore = new Date();
        ca.validity.notAfter = new Date(Date.now() + 86400000);
        const issuer = [
            { name: 'organizationName', value: 'Tizen Association' },
            { shortName: 'OU', value: 'Tizen Association' },
            { shortName: 'CN', value: 'Tizen Developers CA' }
        ];
        ca.setSubject(issuer);
        ca.setIssuer(issuer);
        ca.setExtensions([{ name: 'basicConstraints', cA: true }]);
        ca.sign(caKeys.privateKey, forge.md.sha256.create());
        const directory = join(home, 'share/.tizen-cert/developer');
        mkdirSync(directory, { recursive: true });
        writeFileSync(join(directory, 'tizen-developer-ca-privatekey.pem'),
            forge.pki.encryptRsaPrivateKey(caKeys.privateKey, 'tizencertificatefordevelopercaroqkfwk'));
        writeFileSync(join(directory, 'tizen-developer-ca.cer'), forge.pki.certificateToPem(ca));

        const result = spawnSync(process.execPath, ['-e', `
            const assert = require('node:assert/strict');
            const forge = require('node-forge');
            const Creator = require('./src/tizenCertificateCreator.js');
            (async () => {
                const der = await new Creator().createCertificate({name: 'Test Author', password: 'test-password'});
                const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), 'test-password');
                const keyType = forge.pki.oids.pkcs8ShroudedKeyBag;
                const certType = forge.pki.oids.certBag;
                const key = p12.getBags({bagType: keyType})[keyType][0].key;
                const certificates = p12.getBags({bagType: certType})[certType].map(bag => bag.cert);
                const author = certificates.find(cert => cert.subject.getField('CN').value === 'Test Author');
                const ca = certificates.find(cert => cert.subject.getField('CN').value === 'Tizen Developers CA');
                assert.ok(author && ca, 'the author and CA certificates are preserved');
                assert.equal(key.n.toString(16), author.publicKey.n.toString(16), 'private key must match the author certificate');
                assert.notEqual(key.n.toString(16), ca.publicKey.n.toString(16), 'the CA private key must not be exported');
                assert.ok(ca.verify(author), 'the CA still signs the author certificate');
                const digest = forge.md.sha256.create().update('package signing challenge');
                const signature = key.sign(digest);
                assert.ok(author.publicKey.verify(digest.digest().getBytes(), signature), 'the generated key can sign for the author');
            })().catch(error => { console.error(error); process.exitCode = 1; });
        `], { cwd: join(__dirname, '..'), env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr || result.stdout);
    } finally {
        rmSync(home, { recursive: true, force: true });
    }
});
