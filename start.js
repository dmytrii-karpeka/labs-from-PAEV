

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
    #privateKey1;
    #crypto;
    constructor(listOfCandidates) {
        this.listOfCandidates = {
            "Candidate1": {
                name: "Ilon Musk, who support Ukraine",
                votes: 0
            },
            "Candidate2": {
                name: "Ilon Musk, who support russia",
                votes: 0
            }
        };
        this.#listOfVoters = {
            "voter1": {
                name: "Maria Andrushko",
                age: 18
            },
            "voter2": {
                name: "Pavlo Stonkevych",
                age: 21
            },
            "voter3": {
                name: "Yakym Galayda",
                age: 19
            },
            "voter4": {
                name: "Oksana Styslo",
                age: 42
            },
            "voter5": {
                name: "Vasylyna Prybylo",
                age: 67
            },
            "voter6": {
                name: "Vadym Deter",
                age: 31
            },
            "voter7": {
                name: "Anna Yaroslavna",
                age: 990
            },
            "voter8": {
                name: "Dmytrii Karpeka",
                age: 20
            }
        };
        this.#crypto = require('crypto');
        // this.#privateKey1 = "";
        // this.publicKey1 = this.#generateKeysForRSASign;
    }

    #generateKeysForRSASign() {
        const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.privateKey1 = privateKey;
        // const {publicKey, privateKey} = this.crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
        // this.publicKey = publicKey;
        // this.#privateKey = privateKey;
        return publicKey;
        // return this.#crypto.generateKeySync('aes', {length: 128});
        // console.log(this.publicKey1.export().toString("hex"));
        // const pK = this.#crypto.generateKeySync('aes', {length: 128});
    }
    

    givePublicKey(voterNumb) {
        const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.#listOfVoters[voterNumb].publicK = publicKey;
        this.#listOfVoters[voterNumb].secretKey = privateKey;
        console.log(this.#listOfVoters[voterNumb].name, this.#listOfVoters[voterNumb].secretKey);
        console.log(this.#listOfVoters[voterNumb].publicK);
        return this.#listOfVoters[voterNumb].publicK;
    }



    getBuileten(buileten, voterNumb) {
        const decryptedData = this.#crypto.privateDecrypt({
            key: this.#listOfVoters[voterNumb].secretKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        buileten);
        this.#listOfVoters[voterNumb].voteFor = decryptedData.toString();
        console.log("decrypted data:", decryptedData.toString());
    }
}


const data = "Repto Potroshenko";
const CVK1 = new CVK(['Repto', 'Potroshenko']);
console.log(CVK1.givePublicKey("voter1"));

let crypto = require('crypto');

const encryptedData = crypto.publicEncrypt(
    {
        key: CVK1.givePublicKey("voter1"),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    },
    Buffer.from(data)
);



console.log("encrypted repto: ", encryptedData.toString("base64"));
CVK1.getBuileten(encryptedData, "voter1");

// const ElGamal = require('elgamal');
// const secret = '12323131231';
// const eg = ElGamal.generateAsync();
// const encrypted = eg.encryptAsync(secret);
// const decrypted = eg.decryptAsync(secret);

// console.log(decrypted.toString);

// let crypto2 = require('crypto');
// const pK1 = crypto2.generateKeySync('aes', {length: 128});
// console.log(pK1);
