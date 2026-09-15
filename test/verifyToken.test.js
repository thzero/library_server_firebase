// Needs --experimental-test-module-mocks (set in the package test script):
// verifyToken calls getAuth().verifyIdToken, so firebase-admin has to be stubbed.
import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';

mock.module('firebase-admin/app', { exports: { initializeApp: () => {}, cert: () => ({}) } });
mock.module('firebase-admin/auth', {
	exports: { getAuth: () => ({ verifyIdToken: async () => ({ uid: 'uid-1' }) }) }
});

await import('@thzero/library_common/utility/string.js');
const LibraryMomentUtility = (await import('@thzero/library_common/utility/moment.js')).default;
LibraryMomentUtility.initDateTime();

const FirebaseAuthAdminService = (await import('../auth/index.js')).default;

const inject = (target, name, value) => {
	Object.defineProperty(target, name, { value, writable: true, configurable: true });
	return target;
};

// Returns the service plus the list of exceptions its logger saw, so a swallowed
// throw shows up as a test failure rather than as a quiet null.
const newService = (serviceUsers) => {
	const exceptions = [];
	const service = new FirebaseAuthAdminService();
	inject(service, '_logger', {
		debug() {}, info() {}, info2() {}, warn() {}, error() {}, fatal() {}, trace() {},
		exception(clazz, method, err) { exceptions.push(`${err.constructor.name}: ${err.message}`); }
	});
	inject(service, '_config', { get: () => ({ claims: { useDefault: false } }) });
	service._serviceUsers = serviceUsers;
	return { service, exceptions };
};

// library_server_repository_mongo/baseUser.js:43 sets success = (results !== null),
// so a user who is not in the database yet comes back as a FAILED response.
const notFound = { success: false, results: null, correlationId: 'cid' };

// what updateFromExternal returns after writing the document
// (library_server_repository_mongo/baseUser.js:149-151) - no plan join
const created = { success: true, results: { id: 'uid-1', roles: [ 'user' ], claims: [ 'user' ] }, correlationId: 'cid' };

// what fetchByExternalId returns for someone already there - plan joined on
// (library_server_repository_mongo/baseUser.js:45-51)
const existing = { success: true, results: { id: 'uid-1', roles: [ 'user' ], claims: [ 'user' ], plan: { id: 'free' } }, correlationId: 'cid' };

describe('verifyToken', () => {
	// Regression: the lookup reports "not found" as a failure, so the branch that
	// creates the user was entered with userResponse.results === null. After the
	// create succeeded, the lines below still read userResponse, dereferenced that
	// null, and the outer catch swallowed the TypeError - a user authenticating for
	// the first time was written to the database and still returned unauthenticated.
	it('admits a user it had to create', async () => {
		let updates = 0;
		const { service, exceptions } = newService({
			async fetchByExternalId() { return notFound; },
			async update() { updates++; return created; }
		});

		const results = await service.verifyToken('cid', 'token');

		assert.deepEqual(exceptions, [], 'nothing was thrown and swallowed');
		assert.ok(results, 'verifyToken did not return null');
		assert.equal(results.success, true);
		assert.equal(results.user.id, 'uid-1');
		assert.deepEqual(results.claims, [ 'user' ]);
		assert.equal(updates, 1, 'the user was created exactly once');
	});

	it('does not admit anyone when the create fails', async () => {
		const { service, exceptions } = newService({
			async fetchByExternalId() { return notFound; },
			async update() { return { success: false, results: null }; }
		});
		const results = await service.verifyToken('cid', 'token');
		assert.deepEqual(exceptions, []);
		assert.equal(results.success, false);
		assert.equal(results.user, null);
	});

	it('does not admit anyone when the create reports success but hands back nothing', async () => {
		const { service, exceptions } = newService({
			async fetchByExternalId() { return notFound; },
			async update() { return { success: true, results: null }; }
		});
		const results = await service.verifyToken('cid', 'token');
		assert.deepEqual(exceptions, []);
		assert.equal(results.success, false);
		assert.equal(results.user, null);
	});

	it('uses the lookup for an existing user, keeping the plan join', async () => {
		let updates = 0;
		const { service, exceptions } = newService({
			async fetchByExternalId() { return existing; },
			async update() { updates++; throw new Error('must not be called'); }
		});

		const results = await service.verifyToken('cid', 'token');

		assert.deepEqual(exceptions, []);
		assert.equal(results.success, true);
		assert.deepEqual(results.user.plan, { id: 'free' }, 'the plan the lookup joined survives');
		assert.equal(updates, 0, 'no write for someone already there');
	});

	it('caches the result it just built', async () => {
		let lookups = 0;
		const { service } = newService({
			async fetchByExternalId() { lookups++; return existing; },
			async update() { throw new Error('must not be called'); }
		});
		const first = await service.verifyToken('cid', 'token');
		const second = await service.verifyToken('cid', 'token');
		assert.equal(lookups, 1, 'the second call came from the token cache');
		assert.equal(second, first);
	});
});
