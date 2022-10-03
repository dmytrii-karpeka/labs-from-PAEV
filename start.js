class Voter {
    #eg;
    #voteFor;
    constructor(name, age, theirCVK) {
        this.name = name;
        this.age = age;
        this.theirCVK = theirCVK;
        this.#eg = "";
        this.#voteFor = "";
    }


}

class Candidate extends Voter {
    constructor(name, key) {
        super(name, key);
    }
}

class CVK {
    #listOfVoters;
    #privateKey
    #crypto
    constructor(listOfCandidates) {
        this.listOfCandidates = listOfCandidates;
        this.#listOfVoters = {
            voter1: {
                name: "Maria Andushko",
                age: 18
            },
            voter2: {
                name: "Pavlo Stonkevych",
                age: 21
            }
        };
        this.#crypto = require('crypto');
        this.publicKey1 = this.#generatePublicKey;
    }

    #generatePublicKey() {
        // const {publicKey, privateKey} = this.crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
        // this.publicKey = publicKey;
        // this.#privateKey = privateKey;
        return this.#crypto.generateKeySync('aes', {length: 128});
        // console.log(this.publicKey1.export().toString("hex"));
        // const pK = this.#crypto.generateKeySync('aes', {length: 128});
    }
    

    get givePublicKey() {
        return this.publicKey1;
    }

    #getBuileten(buileten) {

    }
}


const data = "Repto Potroshenko";
const CVK1 = new CVK(['Repto', 'Potroshenko']);
console.log(CVK1.givePublicKey().export().toString("hex"));


// const ElGamal = require('elgamal');
// const secret = '12323131231';
// const eg = ElGamal.generateAsync();
// const encrypted = eg.encryptAsync(secret);
// const decrypted = eg.decryptAsync(secret);

// console.log(decrypted.toString);

// let crypto2 = require('crypto');
// const pK1 = crypto2.generateKeySync('aes', {length: 128});
// console.log(pK1);
