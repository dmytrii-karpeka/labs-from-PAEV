const crypto = require('crypto');
const { ElGamal, Alphabet } = require('./elgamal.js');


class Voter {
    #theirKeys;
    #theirBuileten;
    #hashedBuileten;
        constructor(name, age, theirCVK, message) {
        this.name = name;
        this.age = age;
        this.theirCVK = theirCVK;
        this.message = message;
        this.#theirKeys = { };
        this.#theirBuileten = {
            // signa: { signature and public key of RSA sign } OBJECT
            // buileten: elGamalized with given public key from CVK } STRING
        };
        this.#hashedBuileten = "";
    }

    // get getCVKName() {
    //     return this.theirCVK
    // }

    givePublicKey() {
        return this.#theirKeys.publicRSAKey;
    }

    #generatePublicKey() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.#theirKeys.publicRSAKey = publicKey;
        this.#theirKeys.privateRSAKey = privateKey;
        // console.log(this.#theirKeys.publicRSAKey);
        // console.log(this.#theirKeys.privateRSAKey);  
    }

    #signBuileten() {
        this.#generatePublicKey();
        const verifiableData = this.message;
        const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
            key: this.#theirKeys.privateRSAKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        });
        // console.log(signature.toString("base64"));

        const isVerified = crypto.verify(
            "sha256",
            Buffer.from(verifiableData),
            {
              key: this.#theirKeys.publicRSAKey,
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            signature
          );
          
          this.#theirBuileten.signa = {
            theirSign: signature,
            theirPKey: this.#theirKeys.publicRSAKey
          }
          // isVerified should be `true` if the signature is valid
          console.log("signature verified: ", isVerified);
    }

    #elGamalizeBuileten(channels) {
        const hashedMessage = channels.ch1.encrypt(this.message, channels.ch2.pubKey);
        this.#hashedBuileten = hashedMessage;
        this.#theirBuileten.buileten = this.#hashedBuileten;
    }

    sendBuileten(channels) {
        this.#signBuileten();
        this.#elGamalizeBuileten(channels);
        return this.#theirBuileten;
    }
}


class CVK {
    #listOfVoters;
    constructor(nameOfCVK) {
        this.nameOfCVK = nameOfCVK;
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
                age: 18,
                g: 19
            },
            "voter2": {
                name: "Pavlo Stonkevych",
                age: 21,
                g: 27
            },
            "voter3": {
                name: "Yakym Galayda",
                age: 19,
                g: 26
            },
            "voter4": {
                name: "Oksana Styslo",
                age: 42,
                g: 15
            },
            "voter5": {
                name: "Vasylyna Prybylo",
                age: 67,
                g: 18
            },
            "voter6": {
                name: "Vadym Deter",
                age: 31,
                g: 24
            },
            "voter7": {
                name: "Anna Yaroslavna",
                age: 990,
                g: 11
            },
            "voter8": {
                name: "Dmytrii Karpeka",
                age: 20,
                g: 62
            }
        };
        // this.#privateKey1 = "";
        // this.publicKey1 = this.#generateKeysForRSASign;
    }

    // #generateKeysForRSASign() {
    //     const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
    //     this.privateKey1 = privateKey;
    //     return publicKey;
    // }
    

    givePublicKey(voterNumb) {
        // const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        // this.#listOfVoters[voterNumb].publicK = publicKey;
        // this.#listOfVoters[voterNumb].secretKey = privateKey;
        // console.log(this.#listOfVoters[voterNumb].name, this.#listOfVoters[voterNumb].secretKey);
        // console.log(this.#listOfVoters[voterNumb].publicK);
        // return this.#listOfVoters[voterNumb].publicK;
        let Ch1 = ElGamal(Alphabet, this.#listOfVoters[voterNumb].g);
        let Ch2 = ElGamal(Alphabet, this.#listOfVoters[voterNumb].g);
        this.#listOfVoters[voterNumb].channels = {
            ch1: Ch1,
            ch2: Ch2
        }
        return this.#listOfVoters[voterNumb].channels;
    }

    getBuileten(buileten) {
        // const decryptedData = this.#crypto.privateDecrypt({
        //     key: this.#listOfVoters[voterNumb].secretKey,
        //     padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        //     oaepHash: "sha256",
        // },
        // buileten);
        // this.#listOfVoters[voterNumb].voteFor = decryptedData.toString();
        // console.log("decrypted data:", decryptedData.toString());
        
        // let channelCVK = ElGamal(Alphabet, )
        const encryptedMessage = buileten.buileten;
        this.#listOfVoters.find((v, i) => {

        })


        return buileten;
    }
}


const data = "Repto Potroshenko";
let CVK1 = new CVK("CVK#1");

let voter1 = new Voter("Anna Yaroslavna", 990, "CVK#1", "Repto Potroshenko");
console.log(CVK1.getBuileten(voter1.sendBuileten(CVK1.givePublicKey("voter1"))));

// voter1.givePublicKey();
// console.log(voter1.sendBuileten());












// console.log(CVK1.givePublicKey("voter1"));

// let crypto = require('crypto');

// const encryptedData = crypto.publicEncrypt(
//     {
//         key: CVK1.givePublicKey("voter1"),
//         padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
//         oaepHash: "sha256",
//     },
//     Buffer.from(data)
// );



// console.log("encrypted repto: ", encryptedData.toString("base64"));
// CVK1.getBuileten(encryptedData, "voter1");