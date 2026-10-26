const { createHash, createSign } = require('crypto');
const forge = require('node-forge');

// `#prop` covers a fixed object, so its digest never varies — see `_getPropDigest`.
const AUTHOR_PROP_DIGEST =
    'aXbSAVgmAz0GsBUeZ1UmNDRrxkWhDUVGb45dZcNRq429wX3X+x6kaXT3NdNDTSNVTU+ypkysPMGvQY10fG1EWQ==';
const DISTRIBUTOR_PROP_DIGEST =
    '/r5npk2VVA46QFJnejgONBEh4BWtjrtu9x/IFeLksjWyGmB/cMWKSJWQl7aU3YRQRZ3AesG8gF7qGyvKX9Snig==';

const { DOMParser } = require('@xmldom/xmldom');
const ExclusiveCanonicalization = require('./xml-c14n.js');

function createReference(data, uri) {
    let hashBase64;
    if (uri !== '#prop') {
        const hash = createHash('sha512');
        hash.update(data);
        hashBase64 = hash.digest('base64');
    } else {
        hashBase64 = data;
    }
    const transform = '<Transforms>\n' +
        '<Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></Transform>\n' +
        '</Transforms>\n';

    return `<Reference URI="${uri}">\n` +
        `${uri === '#prop' ? transform : ''}` +
        '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></DigestMethod>\n' +
        `<DigestValue>${hashBase64.replace(/(.{76})/g, '$1\n')}</DigestValue>\n` +
        '</Reference>\n';
}

/**
 * @typedef {Object} File
 * @property {string} uri - The URI path of the file
 * @property {Buffer} data - The data of the file
 */

class Signature {

    /**
     * Creates a signature for a Tizen package. Could be a Widget or a Tizen Package.
     * @param {string} id - ID for the Signature. Can be AuthorSignature or DistributorSignature
     * @param {Array<File>} files - The files which'll get their hashes calculated and the Signature will be added after signing.
     */
    constructor(id, files) {
        this.id = id;
        this.files = files;
        this.references = '';
        this.keyInfo = '';
        this.signedInfo = '';
        this.privateKey = '';
    }

    _getPropXml() {
        return '<Object Id="prop">' +
            '<SignatureProperties xmlns:dsp="http://www.w3.org/2009/xmldsig-properties">' +
            `<SignatureProperty Id="profile" Target="#${this.id}">` +
            '<dsp:Profile URI="http://www.w3.org/ns/widgets-digsig#profile">' +
            '</dsp:Profile>' +
            '</SignatureProperty>' +
            `<SignatureProperty Id="role" Target="#${this.id}">` +
            `<dsp:Role URI="http://www.w3.org/ns/widgets-digsig#role-${this.id === 'AuthorSignature' ? 'author' : 'distributor'}">` +
            '</dsp:Role>' +
            '</SignatureProperty>' +
            `<SignatureProperty Id="identifier" Target="#${this.id}">` +
            '<dsp:Identifier>' +
            '</dsp:Identifier></SignatureProperty></SignatureProperties></Object>';
    }

    _getPropDigest() {
        // The `#prop` reference digest is a constant: the object it covers contains no variable
        // data — only the signature id, and the two ids give the two values below. These are the
        // digests Samsung's own packager emits (verified byte-for-byte against a `tizen package`
        // build of a real TV app), and a set rejects anything else with
        // `install failed[118, -12] ... Invalid signature. Signed with wrong key`.
        //
        // Computing this with `xml-c14n.js` instead produced a different digest, which is why
        // every package this tool signed failed on hardware while its file digests were correct.
        return this.id === 'AuthorSignature' ? AUTHOR_PROP_DIGEST : DISTRIBUTOR_PROP_DIGEST;
    }

    _createReferences() {
        for (const file of this.files) {
            const reference = createReference(file.data, file.uri);
            this.references += reference;
        }

        // Dynamically compute the canonicalized hash of the #prop element
        const propDigest = this._getPropDigest();
        this.references += createReference(propDigest, '#prop');
    }

    /**
     * @param {forge.pkcs12.Pkcs12Pfx} key 
     */
    _addKeyInfo(key) {
        this.keyInfo = '<KeyInfo>\n<X509Data>';
        const seenPems = new Set();

        const appendCert = (cert) => {
            if (!cert) return;
            const pem = forge.pki.certificateToPem(cert);
            if (!seenPems.has(pem)) {
                seenPems.add(pem);
                const clean = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                    .replace(/-----END CERTIFICATE-----/g, '')
                    .replace(/[\r\n]+/g, '')
                    .replace(/(.{76})/g, '$1\n');
                this.keyInfo += `\n<X509Certificate>\n${clean}\n</X509Certificate>`;
            }
        };

        // Extract all certificate bags from PKCS#12 (leaf + intermediate + root CAs)
        if (key.getBags) {
            const certBags = key.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
            for (const bag of certBags) {
                appendCert(bag.cert);
            }
        }

        if (seenPems.size === 0 && key.safeContents) {
            for (const safeContents of key.safeContents) {
                for (const bag of safeContents.safeBags) {
                    if (bag.type === forge.pki.oids.certBag) {
                        appendCert(bag.cert);
                    }
                }
            }
        }

        // Extract private key
        if (key.getBags) {
            const keyBags = (
                key.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ||
                key.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ||
                []
            );
            if (keyBags.length > 0 && keyBags[0].key) {
                this.privateKey = forge.pki.privateKeyToPem(keyBags[0].key);
            }
        }

        if (!this.privateKey && key.safeContents) {
            for (const safeContents of key.safeContents) {
                for (const bag of safeContents.safeBags) {
                    if ((bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) && bag.key) {
                        this.privateKey = forge.pki.privateKeyToPem(bag.key);
                    }
                }
            }
        }

        this.keyInfo += '\n</X509Data>\n</KeyInfo>\n';
    }

    /**
     * @param {forge.pkcs12.Pkcs12Pfx} key 
     */
    _generateSignature(key) {
        this.signedInfo += '<SignedInfo>\n' +
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>\n' +
            '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"></SignatureMethod>\n' +
            this.references +
            '</SignedInfo>\n';

        const signWrapper = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${this.signedInfo}</Signature>`;
        const parser = new DOMParser().parseFromString(signWrapper, 'text/xml');
        const node = parser.documentElement.firstChild;
        const C14N = new ExclusiveCanonicalization();
        const C14NResult = C14N.process(node, {
            defaultNsForPrefix: { ds: 'http://www.w3c.org/2000/09/xmldsig#' }
        });

        const signedKey = createSign('RSA-SHA512').update(C14NResult).sign(key, 'base64');
        this.signedInfo += `<SignatureValue>\n${signedKey.replace(/(.{76})/g, '$1\n')}\n</SignatureValue>\n`;
    }

    _generateSignatureXML() {
        return `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="${this.id}">\n` +
            this.signedInfo +
            this.keyInfo +
            this._getPropXml() + '\n' +
            `</Signature>\n`;
    }

    /**
     * @param {forge.pkcs12.Pkcs12Pfx} key
     */
    async sign(key) {
        await this._createReferences();
        await this._addKeyInfo(key);
        await this._generateSignature(this.privateKey);
        this.files.unshift({
            uri: this.id === 'AuthorSignature' ? 'author-signature.xml' : 'signature1.xml',
            data: Buffer.from(await this._generateSignatureXML())
        });
        return this.files;
    }
}

module.exports = Signature;
