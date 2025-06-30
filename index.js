const { ec: EC } = require('elliptic');
const crypto = require('crypto');

const ec = new EC('secp256k1');


function generateKeyPair() {
  const key = ec.genKeyPair();
  return {
    privateKey: key.getPrivate('hex'),
    publicKey: key.getPublic('hex'),
    keyObject: key
  };
}


function generateAddress(publicKey) {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}


function createMessage(firstName, lastName) {
  return `My name is ${firstName} ${lastName}`;
}


function hashMessage(message) {
  return crypto.createHash('sha256').update(message).digest();
}


function signMessage(key, messageHash) {
  const signature = key.sign(messageHash);
  return signature.toDER('hex');
}


function verifySignature(publicKeyHex, messageHash, signatureHex) {
  const publicKey = ec.keyFromPublic(publicKeyHex, 'hex');
  return publicKey.verify(messageHash, signatureHex);
}



const { privateKey, publicKey, keyObject } = generateKeyPair();
console.log('Private Key:', privateKey);
console.log('Public Key:', publicKey);

const address = generateAddress(publicKey);
console.log('Address:', address);

const firstName = 'Emmanuel';
const lastName = 'Greg';
const message = createMessage(firstName, lastName);
console.log('Message:', message);

const messageHash = hashMessage(message);
console.log('Message Hash:', messageHash.toString('hex'));

const signatureHex = signMessage(keyObject, messageHash);
console.log('Digital Signature:', signatureHex);

const isValid = verifySignature(publicKey, messageHash, signatureHex);
console.log('Signature Valid:', isValid);
