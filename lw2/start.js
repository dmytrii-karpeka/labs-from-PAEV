const crypto = require('crypto');
const { ElGamal, Alphabet } = require('./elgamal.js');


class Voter {
    #theirKeys;
        constructor(id, vote, candidates) {
        //this.name = name;
        //this.age = age;
        this.id = id;
        //this.theirCVK = theirCVK;
        //this.message = message;
        this.vote = vote;
        this.candidates = candidates;
        this.#theirKeys = { };
        this.#theirBuileten = {
            // signa: { signature and public key of RSA sign } OBJECT
            // buileten: elGamalized with given public key from CVK } STRING
        };
        this.#hashedBuileten = "";
        this.#package = [];
    }

    // givePrivateKey() {
    //     return this.#theirKeys.privateRSAKey;
    // }

    #generateKeys() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.#theirKeys.publicRSAKey = publicKey;
        this.#theirKeys.privateRSAKey = privateKey;  
    }

    formPackage() {
        this.#package = [...Array(10).keys].map((v) => {
            return {
                packageNumber: v,
                bul1: {
                    id : this.id,
                    candidate: this.candidates[0],
                    vote: this.vote[0]
                },
                bul2: {
                    id : this.id,
                    candidate: this.candidates[1],
                    vote: this.vote[1]
                }
            }
        });
    }

    #rsaEncryption() {
        this.#generateKeys();
        console.log("Keys generated");
        this.formPackage();
        console.log("package formed");
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
                Buffer.from(v.bul2.vote)
            );
        })  
    }

    deliverPackage() {
        this.#rsaEncryption();
        console.log("Package messages encrypted by safe private key");
        return {
            pKey: this.#deliverKey(),
            package: this.#package
        }
    }

    #deliverKey() {
        return this.#theirKeys.privateRSAKey;
    }

    receiveBuiletensPair(builetensPair) {
        // Decrypt messages
        builetensPair.bul1.vote = crypto.privateDecrypt(
            {
                key: this.#theirKeys.privateRSAKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            builetensPair.bul1.vote
        )

        builetensPair.bul2.vote = crypto.privateDecrypt(
            {
                key: this.#theirKeys.privateRSAKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            builetensPair.bul2.vote
        )

        // Create instance of single buileten from pair
        if (builetensPair.bul1.vote === "Yes" && builetensPair.bul2.vote === "No") {
            giveBuiletenToCVK(builetensPair.bul1);
        } else {
            giveBuiletenToCVK(builetensPair.bul2);
        }
    }

    giveBuiletenToCVK(singleBuileten) {
        // RSA encryption of message before sending
        // using public key given by CVK
        const pKey = builetensPair.signPublicKey;

        singleBuileten.vote = crypto.publicEncrypt(
            {
                key: pKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(singleBuileten.vote)
        );

        return singleBuileten;
    } 
}


class CVK {
    #listOfVoters;
    #statistic;

    #currentPackage;
    #packageObject;
    #currentID;

    rsaPublicKey;
    #rsaPrivateKey;
    constructor() {

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
                id: 123456789,
                pkey: "",
                status: ""
            },
            {
                name: "Pavlo Stonkevych",
                age: 21,
                id: 987654321,
                pkey: "",
                status: ""
            },
            {
                name: "Yakym Galayda",
                age: 19,
                
                id: 123465798,
                pkey: "",
                status: ""
            },
            {
                name: "Oksana Styslo",
                age: 42,
                
                id: 142536798,
                pkey: "",
                status: ""
            },
            {
                name: "Vasylyna Prybylo",
                age: 67,
                
                id: 82365791,
                pkey: "",
                status: ""
            },
            {
                name: "Vadym Detec",
                age: 31,
                id: 143675289,
                pkey: "",
                status: ""
            },
            {
                name: "Anna Yaroslavna",
                age: 990,
                id: 173946825,
                pkey: "",
                status: ""
            },
            {
                name: "Dmytrii Karpeka",
                age: 20,
                id: 741236985,
                pkey: "",
                status: ""
            }];

        this.#statistic = {
            "Possible voters": this.#listOfVoters.length,
            "Voted successfully": 0,
            "Ignored voting": 0,
            "Voted incorrectly": 0,
            "Missed correct ID and same ID in all builetens": 0,
            "Attempt to vote second time": 0
        }

    }


    receivePackage(packageObject) {
        this.#packageObject = packageObject;
        this.#currentPackage = packageObject.package.slice(0, 8);
        this.#currentID = currentPackage[0].bul1.id;
        
        // Checking if voter didn't sent vote already
        this.#listOfVoters.find((voter) => {
            if (voter.id === this.#currentID) {
                if (voter.status === "") {
                    voter.status = "Not signed yet";
                } else if (voter.status === "Messages signed") {
                    this.#statistic["Attempt to vote second time"]++;
                }
            }
            return voter.id === this.#currentID;
        })

        // Checking for same ID on all builetens
        this.#currentPackage.filter((builetens) => {
            let cond1 = this.#currentID === builetens.bul1.id;
            let cond2 = this.#currentID === builetens.bul2.id;
            return cond1 || cond2;
        });

        // If not, then +1 to statistic
        if (this.#packageObject.package.length !== this.#currentPackage.length) {
            this.#statistic["Missed correct ID and same ID in all builetens"]++;
            return 1;
        }

        this.#decryptMessagesInPackage(currentPackage);
    }

    #decryptMessagesInPackage() {
        // Retrieve private key to decipher messages in package
        let currentpKey = this.#packageObject.pKey;
        this.#currentPackage.map((builetensPair) => {
            // Decrypt m1
            builetensPair.bul1.vote = crypto.privateDecrypt({
                key: currentpKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            builetensPair.bul1.vote
            );
        
            // Decrypt m2
            builetensPair.bul2.vote = crypto.privateDecrypt({
                key: currentpKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            builetensPair.bul2.vote
            );
        });

        this.#listOfVoters.find((voter) => {
            return voter.id === this.#currentID;
        }).status = "Messages decrypted";

        // TODO: Check if messages are correct

        this.#signTwoBuiletens();
    }

    #signTwoBuiletens() {
        // Retrive two builetens 
        let twoBuiletens = this.#currentPackage.package[-1];
        // Generate pubK and privK for signing
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048});
        this.rsaPublicKey = publicKey;
        this.#rsaPrivateKey = privateKey;

        // Signing of CVK
        twoBuiletens.bul1.signature = crypto.sign(
            "sha256",
            Buffer.from(twoBuiletens.bul1.vote),
            {
                key: this.#rsaPrivateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            }
        );

        twoBuiletens.bul2.signature = crypto.sign(
            "sha256",
            Buffer.from(twoBuiletens.bul2.vote),
            {
                key: this.#rsaPrivateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            }
        );

        // Add public key to the last two Builetens from package to verify
        twoBuiletens.signPublicKey = this.#rsaPublicKey;

        // Change status for voter
        this.#listOfVoters.find(voter => voter.id === this.#currentID).status = "Messages signed";

        // Return builetens to voter
        this.#returnBuiletens(twoBuiletens);
    }

    #returnBuiletens(builetensPair) {
        return builetensPair;
    }
   
    // Receive final buileten from voter
    receiveFinalBuileten(buileten) {
        // Check for verification
        const isVerified = crypto.verify(
            "sha256",
            Buffer.from(buileten.vote),
            {
                key: this.#rsaPublicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            buileten.signature
        )

        console.log("Signature is", isVerified );
    }
    
        
        
    //     const favourite = this.listOfCandidates.find((candidate) => {
    //         if (candidate.name === decryptedMessage) {
    //             profileOfVoter.voteFor = decryptedMessage;
    //             candidate.votes++;
    //         }
    //         return candidate.name === decryptedMessage;
    //     });

    //     if (!favourite) {
    //         console.warn(`We don't have this option, please pay attention, ${profileOfVoter.name}!`);
    //         return 3;
    //     }
    // }

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


// Main driver code
function eVoting() {
    let CVK0 = new CVK();

    let testVoter = new Voter(
        123456789, 
        ["Yes", "No"], 
        ["Twitter new feature is useful", "No, it's not"]
        );

    testVoter.formPackage();
    let packageOfVoter = testVoter.deliverPackage();
    CVK0.receivePackage(packageOfVoter);
    


    // class Imposter extends Voter {
    //     constructor(name, age, cvk, message) {
    //         super(name, age, cvk, message)
    //         this.name = "imposter";
    //     }
    // }

    // let voters = [
    //     new Voter("Maria Andrushko", 18, "CVK#1", "Elon Musk, who support Ukraine"),
    //     new Voter("Maria Andrushko", 18, "CVK#1", "Elon Musk, who support Ukraine"),
    //     new Voter("Dodik from Kremlin", 4, "CVK#1", "Elon Musk, who support russia"),
    //     new Voter("Pavlo Stonkevych", 21, "CVK#1", "Elon Musk, who support Ukraine"),
    //     new Voter("Yakym Galayda", 19, "CVK#1", "Elon Musk, who support Ukraine"),
    //     new Voter("Oksana Styslo", 42, "CVK#1", "Elon Musk, who support Ukraine"),
    //     new Voter("Vadym Detec", 31, "CVK#1", "Elon Musk is very toxic, I don't like him at all"),
    //     new Voter("Dmytrii Karpeka", 20, "CVK#1", "I agree with Vadym on his statement"),
    //     new Voter("Dmytrii Karpeka", 20, "CVK#1", "I have another option now..."),
    //     new Voter("Vasylyna Prybylo", 67, "CVK#1", "Elon Musk, who support russia"),
    //     new Imposter("Anna Yaroslavna", 990, "CVK#1", "Elon Musk, who support russia")
    // ]

//     voters.map((voter) => eVote(voter, CVK1));
//     statistic["Не проголосувало:"] = CVK1.finalResults();

//     Object.entries(statistic).map(statement => console.log(statement[0] + " " + statement[1]))

//     // Дослідження
//     try {
//         CVK1.listOfVoter();
//     } catch (e) {
//         console.log("Somebody wanted to stole our database!");
// }
}


eVoting();