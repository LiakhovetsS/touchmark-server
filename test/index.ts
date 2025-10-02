import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import Fingerprint from '../dist/index.js';

interface Headers {
  [key: string]: string;
}

describe('Fingerprint Tests', () => {
  const fingerprint = new Fingerprint({
    applyFingerprint: true,
    appSecretKeyList: [
      'DQgjVucwuG2GEEME7muh38CPFWrQXUtNPuNvcCeLR2NWwzyaNcL7BpbKe4XY5k5b',
    ],
    allowedIpList: ['89.184.88.123'],
    whiteListPath: ['/api/user/456'],
    assetsPathPrefixList: ['static'],
    headerSignatureKey: 'x-request-uuid'
  });

  it('Check if applyFingerprint is true', () => {
    assert.strictEqual(fingerprint.isFilterInit, true, 'applyFingerprint should be true');
  });

  it('Valid signature: white path list', () => {
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const method = 'GET';
    const path = '/api/user/456';
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': ''
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(isValid.status, true, 'Signature should be valid');
  });

  it('Invalid signature: non-white path', () => {
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const method = 'GET';
    const path = '/api/user/callback/invalid';
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(isValid.status, false, 'Signature should be invalid for non-white path');
  });

  it('Valid signature: white IP list', () => {
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const method = 'GET';
    const path = '/api/user/456';
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '89.184.88.123',
      'x-forwarded-for': '',
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(isValid.status, true, 'Signature should be valid for white IP list');
  });

  it('Invalid signature: non-white IP', () => {
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const method = 'GET';
    const path = '/api/user/456fdg';
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(isValid.status, false, 'Signature should be invalid for non-white IP');
  });

  it('Valid signature', () => {
    const method = 'GET';
    const path = '/api/user/456dfd';
    const appSignature = 'DQgjVucwuG2GEEME7muh38CPFWrQXUtNPuNvcCeLR2NWwzyaNcL7BpbKe4XY5k5b';
    const timestamp = Math.floor(Date.now() / 1000);
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const message = `${method.toLowerCase()}:${path}:${timestamp}:${userAgent.replace(/\s+/g, '')}`;
    const hmac = crypto.createHmac('sha256', appSignature);
    hmac.update(message);
    const expected = hmac.digest('hex');
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
      'x-request-uuid': Buffer.from(`${timestamp}_${expected}`).toString('base64')
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(isValid.status, true, 'Signature should be valid for path and headers');
  });

  it('Invalid signature: appSignature', () => {
    const method = 'GET';
    const path = '/api/user/456sd';
    const appSignature = 'DQgjVucwuG2GEEME7muh38CPFWrQXUtNPuNvcCeLR2NWwzyaNcL7BpbKe4XY5k5b';
    const timestamp = Math.floor(Date.now() / 1000);
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const message = `${method.toLowerCase()}:${path}:${timestamp}:${userAgent.replace(/\s+/g, '')}`;
    const hmac = crypto.createHmac('sha256', appSignature);
    hmac.update(message);
    const expected = hmac.digest('hex');
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
      'x-request-uuid': Buffer.from(`${timestamp}_${expected}`).toString('base64')
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(fingerprint.isFilterInit === true && !isValid.status, false, 'Invalid request: missing signature');
  });

  it('Fingerprint - disabled with x-request-uuid', () => {
    const method = 'GET';
    const path = '/api/user/456dfg';
    const appSignature = 'DQgjVucwuG2GEEME7muh38CPFWrQXUtNPuNvcCeLR2NWwzyaNcL7BpbKe4XY5k5b';
    const timestamp = Math.floor(Date.now() / 1000);
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const message = `${method.toLowerCase()}:${path}:${timestamp}:${userAgent.replace(/\s+/g, '')}`;
    const hmac = crypto.createHmac('sha256', appSignature);
    hmac.update(message);
    const expected = hmac.digest('hex');
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
      'x-request-uuid': Buffer.from(`${timestamp}_${expected}`).toString('base64')
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(fingerprint.isFilterInit === true && !isValid.status, false, 'Invalid request: missing signature');
  });

  it('Fingerprint - disabled without x-request-uuid', () => {
    const method = 'GET';
    const path = '/api/user/456dgfgd';
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0';
    const headers: Headers = {
      'user-agent': userAgent,
      'x-real-ip': '',
      'x-forwarded-for': '',
    };
    const isValid = fingerprint.decrypt({ method, path, headers });
    assert.strictEqual(fingerprint.isFilterInit === true && !isValid.status, true, 'Invalid request: missing signature');
  });
});

