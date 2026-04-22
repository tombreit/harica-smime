/*!
 * harica-smime/harica-smime-crypto.js
 *
 * Privacy-preserving S/MIME crypto primitives that run entirely in the user's
 * browser. Exposes a single global `window.haricaSmime` with three pure
 * functions:
 *
 *   - generateKeypair(bits = 2048)    -> { publicKey, privateKey }
 *   - buildCsrPem({ publicKey, privateKey, commonName, email }) -> string
 *   - buildPkcs12Bytes({ certPem, privateKey, password, friendlyName })
 *         -> binary string
 *
 * No DOM access. No network. No persistent storage. The private key and
 * PKCS#12 password are held only in variables the caller controls; they must
 * never be sent to the server. The server's role is limited to forwarding
 * the CSR to the CA (HARICA) and returning the signed certificate PEM.
 *
 * Requires: forge.min.js (loaded before this script).
 *
 * License: EUPL-1.2 (see project LICENSE).
 */

(function (global) {
  'use strict';

  if (typeof global.forge === 'undefined') {
    throw new Error(
      'harica-smime-crypto.js requires node-forge. Load forge.min.js first.'
    );
  }

  function generateKeypair(bits) {
    const size = typeof bits === 'number' ? bits : 2048;
    return global.forge.pki.rsa.generateKeyPair(size);
  }

  function buildCsrPem(opts) {
    if (!opts || !opts.publicKey || !opts.privateKey) {
      throw new Error('buildCsrPem: publicKey and privateKey are required');
    }
    if (!opts.commonName || !opts.email) {
      throw new Error('buildCsrPem: commonName and email are required');
    }
    const csr = global.forge.pki.createCertificationRequest();
    csr.publicKey = opts.publicKey;
    csr.setSubject([
      { name: 'commonName',   value: opts.commonName },
      { name: 'emailAddress', value: opts.email }
    ]);
    csr.sign(opts.privateKey);
    return global.forge.pki.certificationRequestToPem(csr);
  }

  function buildPkcs12Bytes(opts) {
    if (!opts || !opts.certPem || !opts.privateKey) {
      throw new Error('buildPkcs12Bytes: certPem and privateKey are required');
    }
    const password = typeof opts.password === 'string' ? opts.password : '';
    const cert = global.forge.pki.certificateFromPem(opts.certPem);
    const asn1 = global.forge.pkcs12.toPkcs12Asn1(
      opts.privateKey,
      cert,
      password,
      {
        algorithm: '3des',
        generateLocalKeyId: true,
        friendlyName: opts.friendlyName || ''
      }
    );
    // Round-trip validation — catches corrupt state before we hand the bytes
    // off to the user.
    global.forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    return global.forge.asn1.toDer(asn1).getBytes();
  }

  global.haricaSmime = {
    generateKeypair: generateKeypair,
    buildCsrPem: buildCsrPem,
    buildPkcs12Bytes: buildPkcs12Bytes
  };
})(typeof window !== 'undefined' ? window : this);
