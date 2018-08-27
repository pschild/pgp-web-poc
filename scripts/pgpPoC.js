let passwordAlice = 'alicesSecret';
let passwordBob = 'bobsSecret';

let keysAlice = {
    privateKey: undefined,
    publicKey: undefined
};

let keysBob = {
    privateKey: undefined,
    publicKey: undefined
};

function generateKeyPair(name, password) {
    let options = {
        userIds: [{name: name}],
        numBits: 2048,
        passphrase: password
    };

    return openpgp.generateKey(options);
}

async function encrypt(senderPrivateKey, senderPassword, receiverPublicKey, message) {
    let publicKeys = (await openpgp.key.readArmored(receiverPublicKey)).keys;

    let privKeyObj = (await openpgp.key.readArmored(senderPrivateKey)).keys[0];
    await privKeyObj.decrypt(senderPassword);

    let options = {
        message: openpgp.message.fromText(message),
        publicKeys: publicKeys,
        privateKeys: [privKeyObj] // for signing the message (optional)
    };

    return openpgp.encrypt(options)
        .then((encryptedMessageObject) => {
            return encryptedMessageObject.data;
        });
}

async function decrypt(receiverPrivateKey, receiverPassword, senderPublicKey, encryptedMessage) {
    let publicKeys = (await openpgp.key.readArmored(senderPublicKey)).keys;

    let privKeyObj = (await openpgp.key.readArmored(receiverPrivateKey)).keys[0];
    await privKeyObj.decrypt(receiverPassword);

    let options = {
        message: await openpgp.message.readArmored(encryptedMessage),
        publicKeys: publicKeys, // for checking the signature (optional)
        privateKeys: [privKeyObj]
    };

    return openpgp.decrypt(options)
        .then((plaintextObject) => {
            return plaintextObject.data;
        });
}

Promise.resolve()
    .then(() => {
        console.log('1) Alice: Generating new key pair...');
        return generateKeyPair('alice', passwordAlice);
    })
    .then((keyPair) => {
        keysAlice.privateKey = keyPair.privateKeyArmored;
        keysAlice.publicKey = keyPair.publicKeyArmored;
        console.log('Done!');
    })
    .then(() => {
        console.log('2) Bob: Generating new key pair...');
        return generateKeyPair('bob', passwordBob);
    })
    .then((keyPair) => {
        keysBob.privateKey = keyPair.privateKeyArmored;
        keysBob.publicKey = keyPair.publicKeyArmored;
        console.log('Done!');
    })
    .then(() => {
        console.log('3) Alice: Encrypting message for bob...');
        return encrypt(keysAlice.privateKey, passwordAlice, keysBob.publicKey, 'Hi Bob, this is Alice! How are you?');
    }).then((encryptedMessage) => {
        console.log('Done! =>', encryptedMessage.substr(0, 110) + '...');
        return encryptedMessage;
    }).then((encryptedMessage) => {
        console.log('4) Bob: Decrypting alice\'s message...');
        return decrypt(keysBob.privateKey, passwordBob, keysAlice.publicKey, encryptedMessage);
    }).then((plaintext) => {
        console.log('Done! =>', plaintext);
    }).then(() => {
        console.log('5) Bob: Encrypting message for alice...');
        return encrypt(keysBob.privateKey, passwordBob, keysAlice.publicKey, 'Hi Alice, this is Bob! I\'m fine!');
    }).then((encryptedMessage) => {
        console.log('Done! =>', encryptedMessage.substr(0, 110) + '...');
        return encryptedMessage;
    }).then((encryptedMessage) => {
        console.log('6) Alice: Decrypting bob\'s message...');
        return decrypt(keysAlice.privateKey, passwordAlice, keysBob.publicKey, encryptedMessage);
    }).then((plaintext) => {
        console.log('Done! =>', plaintext);
    });