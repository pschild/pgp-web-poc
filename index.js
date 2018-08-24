const fs = require('fs');
const openpgp = require('openpgp');

openpgp.initWorker({path: 'openpgp.worker.js'});

function generateKeyPair(name, password) {
    let options = {
        userIds: [{name: name}],
        numBits: 2048,
        passphrase: password
    };

    openpgp.generateKey(options).then((key) => {
        let privkey = key.privateKeyArmored;
        fs.writeFileSync(`privkey_${name}`, privkey);

        let pubkey = key.publicKeyArmored;
        fs.writeFileSync(`pubkey_${name}`, pubkey);

        console.log(`generated key pair for ${name}!`);
    });
}

function encryptMessage(sender, senderPassword, receiver, content) {
    let publicKey = fs.readFileSync(`./pubkey_${receiver}`, 'utf8');
    let privateKey = fs.readFileSync(`./privkey_${sender}`, 'utf8');
    let publicKeys = openpgp.key.readArmored(publicKey).keys;
    let privateKeys = openpgp.key.readArmored(privateKey).keys;

    // decrypt the private key with password
    let success = privateKeys[0].decrypt(senderPassword);

    let options = {
        data: content,
        publicKeys: publicKeys
        /*, privateKeys: privateKeys*/ // when privateKeys is filled, the message will be signed. Then decryption is not (yet) possible in Android
    };

    openpgp.encrypt(options).then((ciphertext) => {
        let encryptedData = ciphertext.data;
        let fileName = `msg_${sender}_to_${receiver}_${new Date().getTime()}`;
        fs.writeFileSync(fileName, encryptedData);
        console.log(fileName);
    });
}

function decryptMessage(receiver, receiverPassword, sender, msgFileName) {
    let publicKey = fs.readFileSync(`./pubkey_${sender}`, 'utf8');
    let privateKey = fs.readFileSync(`./privkey_${receiver}`, 'utf8');
    let publicKeys = openpgp.key.readArmored(publicKey).keys;
    let privateKeys = openpgp.key.readArmored(privateKey).keys;

    // decrypt the private key with password
    let success = privateKeys[0].decrypt(receiverPassword);

    let encryptedMessage = fs.readFileSync(`./${msgFileName}`, 'utf8');
    let options = {
        message: openpgp.message.readArmored(encryptedMessage),
        publicKeys: publicKeys,
        privateKey: privateKeys[0]
    };

    openpgp.decrypt(options).then((plaintext) => {
        console.log(plaintext.data);
    });
}

generateKeyPair('alice', 'alice');
// generateKeyPair('bob', 'bob');
// encryptMessage('alice', 'alice', 'bob', 'Hi Bob! How are you?');
// decryptMessage('alice', 'alice', 'bob', 'enc');