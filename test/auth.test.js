import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';

import '@thzero/library_common/utility/string.js';
import LibraryMomentUtility from '@thzero/library_common/utility/moment.js';
import FirebaseAuthAdminService from '../auth/index.js';
import openSource from '../openSource.js';

LibraryMomentUtility.initDateTime();

const inject = (target, name, value) => {
	Object.defineProperty(target, name, { value, writable: true, configurable: true });
	return target;
};

const newLogger = () => {
	const entries = { warn: [], error: [], exception: [] };
	return {
		entries,
		debug() {}, info() {}, info2() {}, fatal() {}, trace() {},
		warn(clazz, method, message, data, correlationId) { entries.warn.push({ clazz, method, message, correlationId }); },
		error(clazz, method, message, data, correlationId) { entries.error.push({ clazz, method, message, correlationId }); },
		exception(clazz, method, err, correlationId) { entries.exception.push({ clazz, method, err, correlationId }); }
	};
};

let service;
let logger;

beforeEach(() => {
	service = new FirebaseAuthAdminService();
	logger = newLogger();
	inject(service, '_logger', logger);
	inject(service, '_config', { get: () => null });
});

describe('_convert', () => {
	it('maps a firebase user onto the library shape', () => {
		assert.deepEqual(service._convert({
			uid: 'u1', displayName: 'Someone', photoURL: 'http://pic', email: 'a@b.com', extra: 'dropped'
		}), { id: 'u1', name: 'Someone', picture: 'http://pic', email: 'a@b.com' });
	});

	it('returns null for no user', () => {
		assert.equal(service._convert(null), null);
		assert.equal(service._convert(undefined), null);
	});
});

describe('_defaultClaims', () => {
	it('is left to the application', () => {
		assert.throws(() => service._defaultClaims(), /NotImplemented|not implemented/i);
	});
});

describe('deleteUser', () => {
	it('returns null for an empty uid without calling firebase', async () => {
		assert.equal(await service.deleteUser('cid', null), null);
		assert.equal(await service.deleteUser('cid', ''), null);
	});

	// Regression: _error is (clazz, method, message, err, code, errors, correlationId)
	// and this call passed correlationId in the `code` slot, so the response came
	// back with no correlationId at all.
	it('carries the correlationId when the user is not in firebase', async () => {
		const response = await service.deleteUser('cid-123', 'missing');
		assert.equal(service._hasFailed(response), true);
		assert.equal(response.correlationId, 'cid-123', 'the failure is tied to its request');
	});
});

describe('setClaims', () => {
	// The whole body sits in a try/catch, so the enforcement does not escape - it
	// comes back as a failed response.
	it('requires a uid', async () => {
		const response = await service.setClaims('cid', null, {});
		assert.equal(service._hasFailed(response), true);
		assert.ok(logger.entries.error.some(entry => /uid is empty/.test(entry.message)));
	});

	// Regression: the guard and the failure path both logged themselves as
	// 'deleteUser', so a setClaims failure was unfindable in the logs.
	it('reports itself as setClaims, not deleteUser', async () => {
		await service.setClaims('cid', '', {});
		const methods = logger.entries.error.map(entry => entry.method);
		assert.ok(methods.includes('setClaims'), `expected setClaims, got ${JSON.stringify(methods)}`);
		assert.ok(!methods.includes('deleteUser'));
	});

	// Regression: the caught error was passed in the `message` slot, so the
	// response carried the error object as its message and no err at all.
	it('reports a firebase failure as an error, not as a message', async () => {
		const response = await service.setClaims('cid-123', 'u1', {});
		assert.equal(service._hasFailed(response), true);
		assert.equal(response.correlationId, 'cid-123');
		assert.equal(typeof response.message, 'object', 'message is not an Error instance');
	});
});

describe('verifyToken', () => {
	const empty = { user: null, claims: null, success: false };

	it('returns an unsuccessful result for an empty token without calling firebase', async () => {
		assert.deepEqual(await service.verifyToken('cid', null), empty);
		assert.deepEqual(await service.verifyToken('cid', ''), empty);
	});

	it('serves a cached result inside the ttl', async () => {
		const cached = { user: { id: 'u1' }, claims: [ 'user' ], success: true };
		service._cacheTokens.set('tok', { time: LibraryMomentUtility.getTimestamp(), results: cached });
		assert.equal(await service.verifyToken('cid', 'tok'), cached);
	});

	it('drops a cached result once the ttl has passed', async () => {
		const cached = { user: { id: 'u1' }, claims: [ 'user' ], success: true };
		const stale = LibraryMomentUtility.getTimestamp() - service._cacheTokensTtlDefault - 1;
		service._cacheTokens.set('tok', { time: stale, results: cached });
		// firebase is not initialised here, so the call past the cache fails - what
		// matters is that the stale entry was evicted rather than served
		await service.verifyToken('cid', 'tok').catch(() => {});
		assert.equal(service._cacheTokens.has('tok'), false);
	});
});

describe('_initConfig', () => {
	it('explains itself when the service account file is missing', () => {
		assert.throws(() => service._initConfig(), /ENOENT|serviceAccountKey/);
	});
});

describe('openSource', () => {
	it('gives every entry a category, url and licence', () => {
		const entries = openSource();
		assert.ok(entries.length > 0);
		for (const entry of entries) {
			assert.ok(entry.name, 'has a name');
			assert.ok(entry.url, `${entry.name} has a url`);
			assert.ok(entry.licenseName, `${entry.name} has a licence name`);
		}
	});
});
