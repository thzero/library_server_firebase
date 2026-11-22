import fs from 'fs';
import path from 'path';

import { initializeApp, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

import LibraryServerConstants from '@thzero/library_server/constants.js';

import LibraryMomentUtility from '@thzero/library_common/utility/moment.js';

import NotImplementedError from '@thzero/library_common/errors/notImplemented.js';

import Service from '@thzero/library_server/service/index.js';

import TokenExpiredError from '@thzero/library_server/errors/tokenExpired.js';

class FirebaseAuthAdminService extends Service {
	constructor() {
		super();

		// token -> { time, results }. Bounded two ways: entries past the ttl are
		// swept on a timer, and past _cacheTokensMax the oldest are dropped. Before
		// the sweep an entry was only removed when its exact token was presented
		// again, and firebase rotates tokens hourly, so old ones never were: one
		// entry per user per hour, kept for the life of the process.
		this._cacheTokens = new Map();
		this._cacheTokensByUid = new Map();
		this._cacheTokensMax = 10000;
		this._cacheTokensPending = new Map();
		this._cacheTokensSweepHandle = null;
		this._cacheTokensTtlDefault = 5 * 60 * 1000;

		this._serviceUsers = null;
	}

	// The name the boot's cleanup sweep looks for.
	async cleanup(correlationId) {
		this._cacheTokensSweepStop();
		return this._success(correlationId);
	}

	async init(injector) {
		await super.init(injector);

		let serviceAccount = process.env.SERVICE_ACCOUNT_KEY;
		if (serviceAccount)
			serviceAccount = JSON.parse(serviceAccount);
		if (!serviceAccount)
			serviceAccount = this._initConfig();

		initializeApp({
			credential: cert(serviceAccount),
  			databaseURL: serviceAccount.database_url
		});

		this._serviceUsers  = this._injector.getService(LibraryServerConstants.InjectorKeys.SERVICE_USERS);
	}

	async deleteUser(correlationId, uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			await this._auth().deleteUser(uid);
			this.invalidateUser(uid);
			return this._success(correlationId);
		}
		catch(err) {
			if (err && (err.code === 'auth/user-not-found')) {
				this._logger.warn('FirebaseAuthAdminService', 'deleteUser', 'user not found; treating as already deleted', err, correlationId);
				this.invalidateUser(uid);
				return this._success(correlationId);
			}
			return this._error('FirebaseAuthAdminService', 'deleteUser', null, err, null, null, correlationId);
		}
	}

	_auth() {
		return getAuth();
	}

	async getUser(correlationId, uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			const user = await getAuth().getUser(uid);
			if (!user)
				return null;

			return this._convert(user);
		}
		catch(err) {
			this._logger.exception('FirebaseAuthAdminService', 'getUser', err, correlationId);
		}

		return null
	}

	invalidateUser(uid) {
		if (String.isNullOrEmpty(uid))
			return;

		const tokens = this._cacheTokensByUid.get(uid);
		if (!tokens)
			return;

		for (const token of tokens)
			this._cacheTokens.delete(token);
		this._cacheTokensByUid.delete(uid);
	}

	async setClaims(correlationId, uid, claims, replace) {
		try {
			this._enforceNotEmpty('FirebaseAuthAdminService', 'setClaims', uid, 'uid', correlationId);

			// Lookup the user associated with the specified uid.
			const user = await getAuth().getUser(uid);
			if (!user)
				return this._error('FirebaseAuthAdminService', 'setClaims', 'Unable to get user', null, null, null, correlationId);

			let updatedClaims = claims ? { ...claims } : null;
			if (!replace) {
				const customClaims = user.customClaims;
				// merge new claims into existing
				updatedClaims = { ...customClaims, ...claims };
			}

			// The new custom claims will propagate to the user's ID token the
			// next time a new one is issued.
			await getAuth().setCustomUserClaims(uid, updatedClaims);
			this.invalidateUser(uid);

			return this._success(correlationId);
		}
		catch(err) {
			this._logger.exception('FirebaseAuthAdminService', 'setClaims', err, correlationId);
			return this._error('FirebaseAuthAdminService', 'setClaims', null, err, null, null, correlationId);
		}
	}

	async verifyToken(correlationId, token) {
		if (String.isNullOrEmpty(token))
			return this._verifyTokenResults();

		// A plain read. This used to take a mutex around it that the write never
		// took, so it protected nothing and queued every authenticated request
		// behind every other one.
		const cached = this._cacheTokensGet(token);
		if (cached)
			return this._verifyTokenCopy(cached);

		// One verification per token at a time. A page load fires several requests
		// carrying the same fresh token; they share the verification rather than
		// each going to firebase and the user store.
		let pending = this._cacheTokensPending.get(token);
		if (!pending) {
			pending = this._verifyTokenUncached(correlationId, token)
				.finally(() => {
					this._cacheTokensPending.delete(token);
				});
			this._cacheTokensPending.set(token, pending);
		}
		return this._verifyTokenCopy(await pending);
	}

	_cacheTokensGet(token) {
		const data = this._cacheTokens.get(token);
		if (!data)
			return null;

		// https://firebase.google.com/docs/auth/admin/manage-sessions
		if (LibraryMomentUtility.getTimestamp() <= data.expiresAt)
			return data.results;

		this._cacheTokensDelete(token, data);
		return null;
	}

	_cacheTokensDelete(token, data) {
		this._cacheTokens.delete(token);
		const uid = data ? data.uid : null;
		if (!uid)
			return;

		const tokens = this._cacheTokensByUid.get(uid);
		if (!tokens)
			return;
		tokens.delete(token);
		if (tokens.size === 0)
			this._cacheTokensByUid.delete(uid);
	}

	_cacheTokensSet(token, results, uid, expiresAtToken) {
		const now = LibraryMomentUtility.getTimestamp();
		let expiresAt = now + this._cacheTokensTtlDefault;
		if (Number.isFinite(expiresAtToken) && (expiresAtToken < expiresAt))
			expiresAt = expiresAtToken;
		if (expiresAt <= now)
			return;

		this._cacheTokens.set(token, { expiresAt, uid, results });
		if (uid) {
			let tokens = this._cacheTokensByUid.get(uid);
			if (!tokens) {
				tokens = new Set();
				this._cacheTokensByUid.set(uid, tokens);
			}
			tokens.add(token);
		}

		// A Map iterates in insertion order, so the first key is the oldest.
		while (this._cacheTokens.size > this._cacheTokensMax) {
			const oldest = this._cacheTokens.keys().next().value;
			this._cacheTokensDelete(oldest, this._cacheTokens.get(oldest));
		}

		this._cacheTokensSweepStart();
	}

	// Removes what has expired, including tokens that will never be presented
	// again and so would never be evicted on a read.
	_cacheTokensSweep() {
		const now = LibraryMomentUtility.getTimestamp();
		for (const [ token, data ] of this._cacheTokens) {
			if (now > data.expiresAt)
				this._cacheTokensDelete(token, data);
		}

		if (this._cacheTokens.size === 0)
			this._cacheTokensSweepStop();
	}

	_cacheTokensSweepStart() {
		if (this._cacheTokensSweepHandle)
			return;

		this._cacheTokensSweepHandle = setInterval(() => {
			this._cacheTokensSweep();
		}, this._cacheTokensTtlDefault);
		// Must not hold the process open on its own.
		if (this._cacheTokensSweepHandle.unref)
			this._cacheTokensSweepHandle.unref();
	}

	_cacheTokensSweepStop() {
		if (!this._cacheTokensSweepHandle)
			return;

		clearInterval(this._cacheTokensSweepHandle);
		this._cacheTokensSweepHandle = null;
	}

	_verifyTokenCopy(results) {
		if (!results)
			return results;

		return { ...results, user: results.user ? { ...results.user } : results.user };
	}

	_verifyTokenResults() {
		return {
			user: null,
			claims: null,
			success: false
		};
	}

	async _verifyTokenUncached(correlationId, token) {
		try {
			const results = this._verifyTokenResults();

			const configAuth = this._config.get('auth', null) ?? {};
			const checkRevoked = configAuth.checkRevoked !== false;
			let decodedToken;
			try {
				decodedToken = await this._auth().verifyIdToken(token, checkRevoked);
			}
			catch (err) {
				if (err && [ 'auth/id-token-revoked', 'auth/user-disabled', 'auth/user-not-found' ].includes(err.code)) {
					this._logger.warn('FirebaseAuthAdminService', 'verifyToken', err.code, null, correlationId);
					return results;
				}
				throw err;
			}
			if (!decodedToken)
				return results;

			this._logger.debug('FirebaseAuthAdminService', 'verifyToken', 'decodedToken', decodedToken, correlationId);

			const uid = decodedToken.uid;
			if (!uid)
				return results;

			// Getting user from database, which has the claims already, plus plan, etc.
			// Lookup the user associated with the specified uid.
			// const user = await getAuth().getUser(uid);
			// const claims = user.customClaims;

			let userResponse = await this._serviceUsers.fetchByExternalId(correlationId, uid);
			if (this._hasFailed(userResponse) || (this._hasSucceeded(userResponse) && !userResponse.results)) {
				const userUpdateResponse = await this._serviceUsers.update(correlationId, {
					id: uid
				});
				if (this._hasFailed(userUpdateResponse) || (this._hasSucceeded(userUpdateResponse) && !userUpdateResponse.results))
					return results;
				userResponse = userUpdateResponse;
			}

			results.user = userResponse.results;

			results.claims = userResponse.results.claims;
			if (configAuth.claims && configAuth.claims.useDefault && !results.claims)
				results.claims = [ this._defaultClaims() ];

			results.success = true;
			this._cacheTokensSet(token, results, uid, Number.isFinite(decodedToken.exp) ? decodedToken.exp * 1000 : null);
			return results;
		}
		catch(err) {
			this._logger.exception('FirebaseAuthAdminService', 'verifyToken', err, correlationId);
			if (err.code === "auth/id-token-expired")
				throw new TokenExpiredError();
		}

		return null;
	}

	_convert(requestedUser) {
		if (!requestedUser)
			return null;

		const user = {};
		user.id = requestedUser.uid;
		user.name = requestedUser.displayName;
		user.picture = requestedUser.photoURL;
		user.email = requestedUser.email;
		return user;
	}

	_defaultClaims() {
		throw new NotImplementedError();
	}

	_initConfig() {
		const filePath = path.join(process.cwd(), 'config', 'serviceAccountKey.json');
		const file = fs.readFileSync(filePath, 'utf8');
		if (String.isNullOrEmpty(file))
			throw Error('Invalid serviceAccountKey.json configuration file for Firebase; expected in the <app root>/config folder.');

		const config = JSON.parse(file);
		if (!config)
			throw Error('Invalid serviceAccountKey.json file for Firebase config.');

		return config;
	}
}

export default FirebaseAuthAdminService;
