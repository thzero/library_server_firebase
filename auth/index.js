import fs from 'fs';
import path from 'path';

import admin from 'firebase-admin';

import LibraryConstants from '@thzero/library_server/constants.js';

import NotImplementedError from '@thzero/library_common/errors/notImplemented.js';

import Service from '@thzero/library_server/service/index.js';

import TokenExpiredError from '@thzero/library_server/errors/tokenExpired.js';

class FirebaseAuthAdminService extends Service {
	constructor() {
		super();

		this._serviceUsers = null;
	}

	async init(injector) {
		await super.init(injector);

		let serviceAccount = process.env.SERVICE_ACCOUNT_KEY;
		if (serviceAccount)
			serviceAccount = JSON.parse(serviceAccount);
		if (!serviceAccount)
			serviceAccount = this._initConfig();
		admin.initializeApp({
			credential: admin.credential.cert(serviceAccount),
			databaseURL: serviceAccount.database_url
		});

		this._serviceUsers  = this._injector.getService(LibraryConstants.InjectorKeys.SERVICE_USERS);
	}

	async deleteUser(correlationId, uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			const user = await admin.auth().getUser(uid);
			if (!user)
				return null;

			const results = await admin.auth().deleteUser(uid);
			if (!results)
				return this._error('FirebaseAuthAdminService', 'deleteUser', 'Unable to delete user.', null, null, null, correlationId);

			return this._success(correlationId);
		}
		catch(err) {
			if (err.code && err.code === 'auth/user-not-found') {
				this._logger.warn('FirebaseAuthAdminService', 'deleteUser', 'user not found', err, correlationId);
				return this._error('FirebaseAuthAdminService', 'deleteUser', 'user-not-found', err, correlationId);
			}
			this._logger.exception('FirebaseAuthAdminService', 'deleteUser', err, correlationId);
		}

		return this._error('FirebaseAuthAdminService', 'deleteUser', null, null, null, correlationId);
	}

	async getUser(correlationId, uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			const user = await admin.auth().getUser(uid);
			if (!user)
				return null;

			return this._convert(user);
		}
		catch(err) {
			this._logger.exception('FirebaseAuthAdminService', 'getUser', err, correlationId);
		}

		return null
	}

	async setClaims(correlationId, uid, claims, replace) {
		try {
			this._enforceNotEmpty('FirebaseAuthAdminService', 'deleteUser', uid, 'uid', correlationId);

			// Lookup the user associated with the specified uid.
			const user = await admin.auth().getUser(uid);
			if (!user)
				return this._error('FirebaseAuthAdminService', 'deleteUser', 'Unable to get user', null, null, null, correlationId);

			let updatedClaims = claims ? { ...claims } : null;
			if (!replace) {
				const customClaims = user.customClaims;
				// merge new claims into existing
				updatedClaims = { ...customClaims, ...claims };
			}

			// The new custom claims will propagate to the user's ID token the
			// next time a new one is issued.
			await admin.auth().setCustomUserClaims(uid, updatedClaims);

			return this._success(correlationId);
		}
		catch(err) {
			this._logger.exception('FirebaseAuthAdminService', 'setClaims', err, correlationId);
			return this._error('FirebaseAuthAdminService', 'setClaims', err, null, null, null, correlationId);
		}
	}

	async verifyToken(correlationId, token) {
		try {
			const results = {
				user: null,
				claims: null,
				success: false
			}

			if (String.isNullOrEmpty(token))
				return results;

			const decodedToken = await admin.auth().verifyIdToken(token);
			if (!decodedToken)
				return results;

			this._logger.debug('FirebaseAuthAdminService', 'verifyToken', 'decodedToken', decodedToken, correlationId);

			const uid = decodedToken.uid;
			if (!uid)
				return results;

			// Getting user from database, which has the claims already, plus plan, etc.
			// Lookup the user associated with the specified uid.
			// const user = await admin.auth().getUser(uid);
			// const claims = user.customClaims;

			const userResponse = await this._serviceUsers.fetchByExternalId(correlationId, uid);
			if (this._hasFailed(userResponse) || (this._hasSucceeded(userResponse) && !userResponse.results)) {
				const userUpdateResponse = this._serviceUsers.update(correlationId, {
					id: uid
				});
				if (this._hasFailed(userUpdateResponse) || (this._hasSucceeded(userUpdateResponse) && !userUpdateResponse.results))
					return results;
			}

			results.user = userResponse.results;

			results.claims = userResponse.results.claims;
			const configAuth = this._config.get('auth');
			if (configAuth.claims && configAuth.claims.useDefault && !results.claims)
				results.claims = [ this._defaultClaims() ];

			results.success = true;
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
