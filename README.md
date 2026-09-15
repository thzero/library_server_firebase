![GitHub package.json version](https://img.shields.io/github/package-json/v/thzero/library_server_firebase)
![David](https://img.shields.io/david/thzero/library_server_firebase)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# library_server_firebase

Firebase authentication and messaging for [@thzero/library_server](https://github.com/thzero/library_server), built on [firebase-admin](https://firebase.google.com/docs/admin/setup).

Provides the `SERVICE_AUTH` implementation the framework's authentication middleware calls to turn a bearer token into a user.

## Requirements

### NodeJs

[NodeJs](https://nodejs.org) version 22+

### Firebase

[Google Firebase](https://firebase.google.com) provides the social authentication.

* Add a new project
* Under **Authentication**, enable the sign-in methods you intend to support
* Generate a service account key: Project Overview → Settings → Service accounts → **Node.js** → **Generate new private key**

### Installation

[![NPM](https://nodei.co/npm/@thzero/library_server_firebase.png?compact=true)](https://npmjs.org/package/@thzero/library_server_firebase)

```
npm install @thzero/library_server_firebase
```

#### Peer dependencies

* `@thzero/library_common`
* `@thzero/library_common_service`
* `@thzero/library_server`

## What it provides

### `auth/index.js` — `FirebaseAuthAdminService`

| Method | Purpose |
|---|---|
| `verifyToken(correlationId, token)` | Verifies a Firebase ID token, resolves the matching database user, and returns `{ user, claims, success }`. Creates the user on first sign-in. |
| `getUser(correlationId, uid)` | Fetches a Firebase user and maps it to `{ id, name, picture, email }`. |
| `deleteUser(correlationId, uid)` | Deletes a Firebase user. A missing user is reported as `user-not-found` rather than an exception. |
| `setClaims(correlationId, uid, claims, replace)` | Sets custom claims. Merges into the existing claims unless `replace` is true. |
| `_defaultClaims()` | **Abstract.** Throws `NotImplementedError`. Override to supply the claims a user gets when `auth.claims.useDefault` is on. |

**Token cache.** Verified tokens are cached for five minutes (`_cacheTokensTtlDefault`), because Firebase ID tokens are valid for an hour and verifying on every request is wasteful. A stale entry is evicted and re-verified. The cache is per process and per instance.

**Expiry.** An `auth/id-token-expired` from Firebase is rethrown as `TokenExpiredError` from `@thzero/library_server`, which the middleware turns into a distinct response so a client knows to refresh rather than re-authenticate.

**First sign-in.** When the user lookup reports not-found, `_serviceUsers.update` is called to create the record, and the response from that create is what gets returned — so the first request from a new account authenticates like any other.

### `messaging/index.js` — `FirebaseMessagingService`

`setMessage(correlationId, data)` sends a data message through Firebase Cloud Messaging to the device in `registrationToken`. Set `registrationToken` on the service before calling. Failures are logged and `null` is returned.

## Configuration

### Service account

The service account key is read in this order:

1. The `SERVICE_ACCOUNT_KEY` environment variable, holding the JSON itself. Use this in hosted environments.
2. `<app root>/config/serviceAccountKey.json`. Use this locally, and keep it out of source control.

`databaseURL` is taken from the key's own `database_url` field.

### Claims

```json
{
    "app": {
        "auth": {
            "claims": {
                "check": false,
                "useDefault": false
            }
        }
    }
}
```

* **`claims.useDefault`** — when `true` and the resolved user carries no claims, `_defaultClaims()` supplies them. Leave it `false` unless you have overridden that method, or verification will throw.

## Wiring it up

Register it as the auth service from your `BootMain` derived class, so the authentication middleware resolves it:

```js
import firebaseAuthService from '@thzero/library_server_firebase/auth/index.js';

class AppBootMain extends BootMain {
    async _initServices() {
        await super._initServices();
        this._injectService(LibraryServerConstants.InjectorKeys.SERVICE_AUTH, new firebaseAuthService());
    }
}
```

The service resolves `SERVICE_USERS` during `init`, so a users service must be registered too.

## Development

```
npm run lint       # eslint .
npm run lint:fix   # eslint . --fix
npm test           # node --experimental-test-module-mocks --test "test/*.test.js"
```

The test script carries `--experimental-test-module-mocks` because the `verifyToken` suite stubs `firebase-admin` rather than contacting Firebase.
