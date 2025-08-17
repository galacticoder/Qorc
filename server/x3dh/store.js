const bundles = new Map(); //username { bundle, oneTimeQueue: OneTimePreKey[] } //use in db later instead of memory

export function publishBundle(username, bundle) {
	const oneTimeQueue = Array.isArray(bundle.oneTimePreKeys) ? [...bundle.oneTimePreKeys] : [];
	const sanitized = {
		username,
		identityEd25519Public: bundle.identityEd25519Public,
		identityX25519Public: bundle.identityX25519Public,
		signedPreKey: bundle.signedPreKey,
		ratchetPublic: bundle.ratchetPublic || bundle.identityX25519Public,
		oneTimePreKeys: oneTimeQueue,
	};
	bundles.set(username, { bundle: sanitized, oneTimeQueue });
}

export function takeBundleForRecipient(username) {
	const entry = bundles.get(username);
	if (!entry) return null;
	const { bundle, oneTimeQueue } = entry;
	const oneTime = oneTimeQueue.shift();
	return {
		username,
		identityEd25519Public: bundle.identityEd25519Public,
		identityX25519Public: bundle.identityX25519Public,
		signedPreKey: bundle.signedPreKey,
		ratchetPublic: bundle.ratchetPublic,
		oneTimePreKey: oneTime || null,
	};
}

export function hasBundle(username) {
	return bundles.has(username);
}


