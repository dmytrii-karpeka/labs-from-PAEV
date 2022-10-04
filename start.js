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
        const verifiableData = this.name;
        const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
            key: this.#theirKeys.privateRSAKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        });
        // console.log(signature.toString("base64"));

        // const isVerified = crypto.verify(
        //     "sha256",
        //     Buffer.from(verifiableData),
        //     {
        //       key: this.#theirKeys.publicRSAKey,
        //       padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        //     },
        //     signature
        //   );
          
          this.#theirBuileten.signa = {
            theirSign: signature,
            theirPKey: this.#theirKeys.publicRSAKey
          }
          // isVerified should be `true` if the signature is valid
        //   console.log("signature verified: ", isVerified);
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
        this.listOfCandidates = [
            {
                name: "Ilon Musk, who support Ukraine",
                votes: 0
            },
            {
                name: "Ilon Musk, who support russia",
                votes: 0
            }
        ];
        this.#listOfVoters = [
            {
                name: "Maria Andrushko",
                age: 18,
                channels: {
                    ch1: ElGamal(Alphabet, 19),
                    ch2: ElGamal(Alphabet, 19)
                }
            },
            {
                name: "Pavlo Stonkevych",
                age: 21,
                channels: {
                    ch1: ElGamal(Alphabet, 27),
                    ch2: ElGamal(Alphabet, 27)
                }
            },
            {
                name: "Yakym Galayda",
                age: 19,
                channels: {
                    ch1: ElGamal(Alphabet, 26),
                    ch2: ElGamal(Alphabet, 26)
                }
            },
            {
                name: "Oksana Styslo",
                age: 42,
                channels: {
                    ch1: ElGamal(Alphabet, 15),
                    ch2: ElGamal(Alphabet, 15)
                }
            },
            {
                name: "Vasylyna Prybylo",
                age: 67,
                channels: {
                    ch1: ElGamal(Alphabet, 18),
                    ch2: ElGamal(Alphabet, 18)
                }
            },
            {
                name: "Vadym Detec",
                age: 31,
                channels: {
                    ch1: ElGamal(Alphabet, 24),
                    ch2: ElGamal(Alphabet, 24)
                }
            },
            {
                name: "Anna Yaroslavna",
                age: 990,
                channels: {
                    ch1: ElGamal(Alphabet, 11),
                    ch2: ElGamal(Alphabet, 11)
                }
            },
            {
                name: "Dmytrii Karpeka",
                age: 20,
                channels: {
                    ch1: ElGamal(Alphabet, 62),
                    ch2: ElGamal(Alphabet, 62)
                }
            }];
        
        // this.#privateKey1 = "";
        // this.publicKey1 = this.#generateKeysForRSASign;
    }

    // #generateKeysForRSASign() {
    //     const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
    //     this.privateKey1 = privateKey;
    //     return publicKey;
    // }
    

    givePublicKey(voterName) {
        // const { publicKey, privateKey } = this.#crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        // this.#listOfVoters[voterNumb].publicK = publicKey;
        // this.#listOfVoters[voterNumb].secretKey = privateKey;
        // console.log(this.#listOfVoters[voterNumb].name, this.#listOfVoters[voterNumb].secretKey);
        // console.log(this.#listOfVoters[voterNumb].publicK);
        // return this.#listOfVoters[voterNumb].publicK;
        let indexOfName;
        const canFindName = this.#listOfVoters.find((v, i) => {
            indexOfName = i;
            return v.name === voterName;
        });
        if (canFindName) {
            return this.#listOfVoters[indexOfName].channels;
        } else {
            console.warn(`Sorry, but you cannot vote at this CVK, ${voterName}`);
            return 0;
        }
    };

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

        const verification = this.#listOfVoters.find((voterN, i) => {
            const isVerified = crypto.verify(
                "sha256",
                Buffer.from(voterN.name),
                {
                    key: buileten.signa.theirPKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                },
                buileten.signa.theirSign
            )

            if (isVerified) {
                this.#listOfVoters[i].status = "checked";
            }
            // console.log(isVerified);
            return isVerified;
        });

        // console.log(verification);

        return buileten;
    }
}


const data = "Repto Potroshenko";
let CVK1 = new CVK("CVK#1");

let voter1 = new Voter("Anna Yaroslavna", 990, "CVK#1", "Repto Potroshenko");
// let voter2 = new Voter("Somebody", 12, "CVK#1", "Repto Potroshenko");

let voters = [
    new Voter(),
    new Voter(),
    new Voter(),
    new Voter(),
    new Voter(),
    new Voter(),
]
// let voter2 = new Voter("Anna Yaroslavna", 990, "CVK#1", "Repto Potroshenko");
CVK1.getBuileten(voter1.sendBuileten(CVK1.givePublicKey(voter1.name)));
// CVK1.getBuileten(voter2.sendBuileten(CVK1.givePublicKey(voter2.name)));


let statistic = {
    "Не проголосувало:": 0,
    "Проголосувало неправильно": 0,
    "Виборець не має права голосувати": 0,
    "Виборець хоче проголосувати повторно": 0,
    "Виборець хоче проголосувати замість іншого виборця": 0,
};


function eVoting(voter, cvk) {
    const pk = cvk.givePublicKey(voter.name);
    if (pk === 0) {
        statistic["Виборець не має права голосувати"]++;
        return 0;
    }

    const sendedBuileten = voter.sendBuileten(pk);


}

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