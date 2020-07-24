import admin from 'firebase-admin';

import LibraryConstants from '@thzero/library/constants';

import NotImplementedError from '@thzero/library_common/errors/notImplemented';

import Service from '@thzero/library/service/index';

import TokenExpiredError from '@thzero/library/errors/tokenExpired';

class FirebaseAuthAdminService extends Service {
	async deleteUser(uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			const user = await admin.auth().getUser(uid);
			if (!user)
				return null;

			const results = await admin.auth().deleteUser(uid);
			if (!results)
				return this._error();

			return this._success();
		}
		catch(err) {
			if (err.code && err.code === 'auth/user-not-found') {
				this._logger.warn(err);
				return this._success('user-not-found');
			}
			this._logger.exception(err);
		}

		return this._error();
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
	}

	async getUser(uid) {
		try {
			if (String.isNullOrEmpty(uid))
				return null;

			const user = await admin.auth().getUser(uid);
			if (!user)
				return null;

			return this._convert(user);
		}
		catch(err) {
			this._logger.exception(err);
		}

		return null
	}

	async setClaims(uid, claims, replace) {
		try {
			if (String.isNullOrEmpty(uid))
				return this._error();

			// Lookup the user associated with the specified uid.
			const user = await admin.auth().getUser(uid);
			if (!user)
				return this._error();

			let updatedClaims = claims ? { ...claims } : null;
			if (!replace) {
				const customClaims = user.customClaims;
				// merge new claims into existing
				updatedClaims = { ...customClaims, ...claims };
			}

			// The new custom claims will propagate to the user's ID token the
			// next time a new one is issued.
			await admin.auth().setCustomUserClaims(uid, updatedClaims);

			return this._initResponse();
		}
		catch(err) {
			this._logger.exception(err);
			return this._error();
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

			this._logger.debug('verifyToken', decodedToken);

			const uid = decodedToken.uid;
			if (!uid)
				return results;

			// Getting user from database, which has the claims already, plus plan, etc.
			// Lookup the user associated with the specified uid.
			// const user = await admin.auth().getUser(uid);
			// const claims = user.customClaims;

			const userResponse = await this._serviceUser.fetchByExternalId(correlationId, uid);
			if (!userResponse.success || !userResponse.results) {
				const userUpdateResponse = this._serviceUser.update(correlationId, {
					id: uid
				})
				if (!userUpdateResponse.success || !userUpdateResponse.results)
					return userUpdateResponse;
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
			this._logger.exception(err);
			if (err.code === "auth/id-token-expired")
				throw new TokenExpiredError();
		}

		return null
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
		throw new NotImplementedError();
	}

	get _serviceUser() {
		return this._injector.getService(LibraryConstants.InjectorKeys.SERVICE_USERS);
	}
}

export default FirebaseAuthAdminService;
