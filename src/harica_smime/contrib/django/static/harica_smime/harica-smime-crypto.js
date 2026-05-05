/*!
 * harica-smime/harica-smime-crypto.js
 *
 * Privacy-preserving S/MIME crypto primitives that run entirely in the user's
 * browser. Exposes a single global `window.haricaSmime` with four pure
 * functions:
 *
 *   - generateKeypair(bits = 2048)    -> { publicKey, privateKey }
 *   - buildCsrPem({ publicKey, privateKey, commonName, email }) -> string
 *   - friendlyNameFromCert(certPem)   -> string
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

  // Pulls the friendlyName for a HARICA-issued S/MIME cert straight from the
  // cert itself: CN if present (natural_legal_lcp), else emailAddress
  // (email_only). Throws when neither is available — callers should pass the
  // result into buildPkcs12Bytes rather than constructing a friendlyName from
  // form fields, which can drift from the cert's actual subject.
  function friendlyNameFromCert(certPem) {
    if (!certPem) {
      throw new Error('friendlyNameFromCert: certPem is required');
    }
    const cert = global.forge.pki.certificateFromPem(certPem);
    const cn = cert.subject.getField({ name: 'commonName' });
    if (cn && cn.value) {
      return cn.value;
    }
    const email = cert.subject.getField({ name: 'emailAddress' });
    if (email && email.value) {
      return email.value;
    }
    throw new Error(
      'friendlyNameFromCert: cert subject has neither commonName nor emailAddress'
    );
  }

  function buildPkcs12Bytes(opts) {
    if (!opts || !opts.certPem || !opts.privateKey) {
      throw new Error('buildPkcs12Bytes: certPem and privateKey are required');
    }
    if (typeof opts.friendlyName !== 'string' || opts.friendlyName === '') {
      throw new Error('buildPkcs12Bytes: friendlyName is required');
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
        friendlyName: opts.friendlyName
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
    friendlyNameFromCert: friendlyNameFromCert,
    buildPkcs12Bytes: buildPkcs12Bytes
  };
})(typeof window !== 'undefined' ? window : this);
