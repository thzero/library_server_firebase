import admin from 'firebase-admin';

import Service from '@thzero/library_server/service/index';

class FirebaseMessagingService extends Service {
	constructor() {
		super();

		this.registrationToken = null;
	}

	async setMessage(correlationId, data) {
		try {
			var message = {
				data: data,
				token: this.registrationToken
			};

			// Send a message to the device corresponding to the provided registration token.
			const response = await admin.messaging().send(message);
			this._logger.debug('FirebaseMessagingService', 'setMessage', 'Successfully sent message', response, correlationId);
		}
		catch (err) {
			this._logger.exception('FirebaseMessagingService', 'setMessage', err, correlationId);
		}

		return null
	}
}

export default FirebaseMessagingService;
