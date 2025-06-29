const EC = require('elliptic').ec;
const crypto = require('crypto');

const ec = new EC('secp256k1');


const key = ec.genKeyPair();
const privateKey = key.getPrivate('hex');
console.log('Private Key:', privateKey);


const publicKey = key.getPublic('hex');
console.log('Public Key:', publicKey);


const address = crypto.createHash('sha256').update(publicKey).digest('hex');
console.log('Address:', address);

const firstName = 'Emmanuel';
const lastName = 'Greg';
const message = `My name is ${firstName} ${lastName}`;
console.log('Message:', message);


const messageHash = crypto.createHash('sha256').update(message).digest();
console.log('Message Hash:', messageHash.toString('hex'));


const signature = key.sign(messageHash);
const signatureHex = signature.toDER('hex');
console.log('Digital Signature:', signatureHex);

const isValid = ec.keyFromPublic(publicKey, 'hex').verify(messageHash, signature);
console.log('Signature Valid:', isValid);
