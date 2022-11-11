const crypto = require('crypto');
const { ElGamal, Alphabet } = require('./elgamal.js');


class Voter {
    #theirKeys;
    #theirBuileten;
    #hashedBuileten;
        constructor(name, age, id, theirCVK, vote) {
        this.name = name;
        this.age = age;
        this.id = id;
        this.theirCVK = theirCVK;
        //this.message = message;
        this.vote = vote;
        this.#theirKeys = { };
        this.#theirBuileten = {
            // signa: { signature and public key of RSA sign } OBJECT
            // buileten: elGamalized with given public key from CVK } STRING
        };
        this.#hashedBuileten = "";
        this.#package = [];
    }

    givePrivateKey() {
        return this.#theirKeys.publicRSAKey;
    }

    #generateKeys() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.#theirKeys.publicRSAKey = publicKey;
        this.#theirKeys.privateRSAKey = privateKey;  
    }

    formPackage(candidates) {
        this.#package = [...Array(10).keys].map((v) => {
            return {
                packageNumber: v,
                bul1: {
                    id : this.id,
                    candidate: candidates[0],
                    vote: this.vote[0]
                },
                bul2: {
                    id : this.id,
                    candidate: candidates[1],
                    vote: this.vote[1]
                }
            }
        });
    }

    #rsaEncryption() {
        this.#generateKeys();
        this.formPackage();
        this.#package.map((v) => {
            v.bul1.vote = crypto.publicEncrypt(
                {
                    key: this.#theirKeys.publicRSAKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                Buffer.from(v.bul1.vote)
            );
            v.bul2.vote = crypto.publicEncrypt(
                {
                    key: this.#theirKeys.publicRSAKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                Buffer.from(v.bul1.vote)
            );
        })
    }

    deliverPackage() {
        this.#rsaEncryption();
        return this.#package
    }
 
    // #signBuileten() {
    //     this.#generatePublicKey();
    //     const verifiableData = this.name;
    //     const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
    //         key: this.#theirKeys.privateRSAKey,
    //         padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    //     });
          
    //       this.#theirBuileten.signa = {
    //         theirSign: signature,
    //         theirPKey: this.#theirKeys.publicRSAKey
    //       }
    // }

    // #elGamalizeBuileten(channels) {
    //     const hashedMessage = channels.ch1.encrypt(this.message, channels.ch2.pubKey);
    //     this.#hashedBuileten = hashedMessage;
    //     this.#theirBuileten.buileten = this.#hashedBuileten;
    // }

    // sendBuileten(channels) {
    //     this.#signBuileten();
    //     this.#elGamalizeBuileten(channels);
    //     return this.#theirBuileten;
    // }
}


class CVK {
    #listOfVoters;
    constructor(nameOfCVK) {
        this.nameOfCVK = nameOfCVK;
        this.listOfCandidates = [
            {
                name: "Twitter new feature is useful",
                votes: 0
            },
            {
                name: "No, it's not",
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
                },
                id: 123456789
            },
            {
                name: "Pavlo Stonkevych",
                age: 21,
                channels: {
                    ch1: ElGamal(Alphabet, 27),
                    ch2: ElGamal(Alphabet, 27)
                },
                id: 987654321
            },
            {
                name: "Yakym Galayda",
                age: 19,
                channels: {
                    ch1: ElGamal(Alphabet, 26),
                    ch2: ElGamal(Alphabet, 26)
                },
                id: 123465798
            },
            {
                name: "Oksana Styslo",
                age: 42,
                channels: {
                    ch1: ElGamal(Alphabet, 15),
                    ch2: ElGamal(Alphabet, 15)
                },
                id: 142536798
            },
            {
                name: "Vasylyna Prybylo",
                age: 67,
                channels: {
                    ch1: ElGamal(Alphabet, 18),
                    ch2: ElGamal(Alphabet, 18)
                },
                id: 82365791
            },
            {
                name: "Vadym Detec",
                age: 31,
                channels: {
                    ch1: ElGamal(Alphabet, 24),
                    ch2: ElGamal(Alphabet, 24)
                },
                id: 143675289
            },
            {
                name: "Anna Yaroslavna",
                age: 990,
                channels: {
                    ch1: ElGamal(Alphabet, 11),
                    ch2: ElGamal(Alphabet, 11)
                },
                id: 173946825
            },
            {
                name: "Dmytrii Karpeka",
                age: 20,
                channels: {
                    ch1: ElGamal(Alphabet, 62),
                    ch2: ElGamal(Alphabet, 62)
                },
                id: 741236985
            }];
    }
   

    givePublicKey(voterName) {
        let indexOfName; 
        const canFindName = this.#listOfVoters.find((v, i) => {
            indexOfName = i;
            return v.name === voterName;
        });

        const checkedStatus = this.#listOfVoters[indexOfName].status === "checked";
        // const verified = this.#listOfVoters[indexOfName].verified === "veried";

        // if (checkedStatus && !verified) {
        //     console.warn(`You're imposter, ${voterName}`);
        //     return 7;
        // } else 
        if (checkedStatus) {
            console.warn(`Don't try to fool us, you're trying to vote second time or you're imposter, ${voterName}`);
            return 1;
        } else if (!canFindName) {
            console.warn(`Sorry, but you cannot vote at this CVK, ${voterName}`);
            return 0;
        } else if (canFindName) {
            return this.#listOfVoters[indexOfName].channels;
        }
    };

    getBuileten(buileten) {
        const encryptedMessage = buileten.buileten;

        const profileOfVoter = this.#listOfVoters.find((voterN, i) => {
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
                // this.#listOfVoters[i].verified = "verified";
                this.#listOfVoters[i].status = "checked";
            }

            return isVerified;
        });

        const decryptedMessage = profileOfVoter.channels.ch2.decrypt(buileten.buileten);
        
        
        const favourite = this.listOfCandidates.find((candidate) => {
            if (candidate.name === decryptedMessage) {
                profileOfVoter.voteFor = decryptedMessage;
                candidate.votes++;
            }
            return candidate.name === decryptedMessage;
        });

        if (!favourite) {
            console.warn(`We don't have this option, please pay attention, ${profileOfVoter.name}!`);
            return 3;
        }
    }

    finalResults() {


        console.log(`
        ~~~~~
        ${this.listOfCandidates[0].name} has scored ${this.listOfCandidates[0].votes}!
        ${this.listOfCandidates[1].name} has scored ${this.listOfCandidates[1].votes}!

        The winner is ${this.listOfCandidates[0].votes >= this.listOfCandidates[1].votes ? this.listOfCandidates[0].name : this.listOfCandidates[1].name}!

        ~~~~~
        `)
        return this.#listOfVoters.length - this.#listOfVoters.filter((persona) => {
            return persona.status === "checked"
        }).length
    }
}


let statistic = {
    "Явка на вибори:" : 0,
    "Не проголосувало:": 0,
    "Проголосувало неправильно": 0,
    "Виборець не має права голосувати": 0,
    "Виборець хоче проголосувати повторно": 0,
};

function eVote(voter, cvk) {
    const pk = cvk.givePublicKey(voter.name);
    if (pk === 0) {
        statistic["Виборець не має права голосувати"]++;
        statistic["Явка на вибори:"]++;
        return 0;
    } else if (pk === 1) {
        statistic["Виборець хоче проголосувати повторно"]++;
        return 0;
    } 

    const sendedBuileten = voter.sendBuileten(pk);

    const gottenBuileten = cvk.getBuileten(sendedBuileten);

    if (gottenBuileten === 3) {
        statistic["Проголосувало неправильно"]++;
        statistic["Явка на вибори:"]++;
        return 0;
    }

    statistic["Явка на вибори:"]++;
}

function eVoting() {
    let CVK1 = new CVK("CVK#1");

    class Imposter extends Voter {
        constructor(name, age, cvk, message) {
            super(name, age, cvk, message)
            this.name = "imposter";
        }
    }

    let voters = [
        new Voter("Maria Andrushko", 18, "CVK#1", "Elon Musk, who support Ukraine"),
        new Voter("Maria Andrushko", 18, "CVK#1", "Elon Musk, who support Ukraine"),
        new Voter("Dodik from Kremlin", 4, "CVK#1", "Elon Musk, who support russia"),
        new Voter("Pavlo Stonkevych", 21, "CVK#1", "Elon Musk, who support Ukraine"),
        new Voter("Yakym Galayda", 19, "CVK#1", "Elon Musk, who support Ukraine"),
        new Voter("Oksana Styslo", 42, "CVK#1", "Elon Musk, who support Ukraine"),
        new Voter("Vadym Detec", 31, "CVK#1", "Elon Musk is very toxic, I don't like him at all"),
        new Voter("Dmytrii Karpeka", 20, "CVK#1", "I agree with Vadym on his statement"),
        new Voter("Dmytrii Karpeka", 20, "CVK#1", "I have another option now..."),
        new Voter("Vasylyna Prybylo", 67, "CVK#1", "Elon Musk, who support russia"),
        new Imposter("Anna Yaroslavna", 990, "CVK#1", "Elon Musk, who support russia")
    ]

    voters.map((voter) => eVote(voter, CVK1));
    statistic["Не проголосувало:"] = CVK1.finalResults();

    Object.entries(statistic).map(statement => console.log(statement[0] + " " + statement[1]))

    // Дослідження
    try {
        CVK1.listOfVoter();
    } catch (e) {
        console.log("Somebody wanted to stole our database!");
}
}


eVoting();