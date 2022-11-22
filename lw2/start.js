const crypto = require('crypto');

class Voter {
    #theirKeys;
    #package;
        constructor(id, vote, candidates) {
        //this.name = name;
        //this.age = age;
        this.id = id;
        //this.theirCVK = theirCVK;
        //this.message = message;
        this.vote = vote;
        this.candidates = candidates;
        this.#theirKeys = { };
        //this.#theirBuileten = {
            // signa: { signature and public key of RSA sign } OBJECT
            // buileten: elGamalized with given public key from CVK } STRING
        //};
        //this.#hashedBuileten = "";
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
        this.#package = [...Array(10).keys()].map((v) => {
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
        //this.formPackage();
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
        builetensPair.bul1.encryptedVote = builetensPair.bul1.vote;
        builetensPair.bul2.encryptedVote = builetensPair.bul2.vote;
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
        if (builetensPair.bul1.vote.toString() === "Yes") {
            return this.giveBuiletenToCVK(builetensPair.bul1, builetensPair.signPublicKey);
        } else {
            return this.giveBuiletenToCVK(builetensPair.bul2, builetensPair.signPublicKey);
        }
    }

    giveBuiletenToCVK(singleBuileten, key) {
        // RSA encryption of message before sending
        // using public key given by CVK
        const publicKey = key;

        singleBuileten.vote = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(singleBuileten.vote)
        );

        return singleBuileten;
    } 
}

class SomeVoter {
    #theirKeys;
    #package;
        constructor(id, vote, candidates) {
        //this.name = name;
        //this.age = age;
        this.id = id;
        //this.theirCVK = theirCVK;
        //this.message = message;
        this.vote = vote;
        this.candidates = candidates;
        this.#theirKeys = { };
        //this.#theirBuileten = {
            // signa: { signature and public key of RSA sign } OBJECT
            // buileten: elGamalized with given public key from CVK } STRING
        //};
        //this.#hashedBuileten = "";
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
        this.#package = [...Array(9).keys()].map((v) => {
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
        this.#package.unshift({
            packageNumber: 9,
            bul1: {
                id: 1111111,
                candidate: this.candidates[0],
                    vote: this.vote[0]
            },
            bul2: {
                id : 1111111,
                candidate: this.candidates[1],
                vote: this.vote[1]
            }
        })
    }

    #rsaEncryption() {
        this.#generateKeys();
        //this.formPackage();
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
        builetensPair.bul1.encryptedVote = builetensPair.bul1.vote;
        builetensPair.bul2.encryptedVote = builetensPair.bul2.vote;
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
        if (builetensPair.bul1.vote.toString() === "Yes") {
            return this.giveBuiletenToCVK(builetensPair.bul1, builetensPair.signPublicKey);
        } else {
            return this.giveBuiletenToCVK(builetensPair.bul2, builetensPair.signPublicKey);
        }
    }

    giveBuiletenToCVK(singleBuileten, key) {
        // RSA encryption of message before sending
        // using public key given by CVK
        const publicKey = key;

        singleBuileten.vote = crypto.publicEncrypt(
            {
                key: publicKey,
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
    #rsaPublicKey;
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
                id: 1111,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 2222,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 4321,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 1234,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 123456789,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 987654321,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {                
                id: 123465798,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 142536798,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 82365791,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 143675289,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 173946825,
                pkey: "",
                status: "",
                theirBuileten: {}
            },
            {
                id: 741236985,
                pkey: "",
                status: "",
                theirBuileten: {}
            }];

        this.#statistic = {
            "Possible voters": this.#listOfVoters.length,
            "Voted successfully": 0,
            "Ignored voting": 0,
            "Voted incorrectly": 0,
            "Missed correct ID and same ID in all builetens": 0,
            "Attempt to vote second time": 0,
            "Vote blind sign is incorrect and CVK can not accept and count that vote": 0
        }

    }


    receivePackage(packageObject) {
        this.#packageObject = packageObject;
        this.#currentPackage = packageObject.package.slice(0, 9);
        this.#currentID = this.#currentPackage[0].bul1.id;
        
        // Checking if voter didn't sent vote already
        this.#listOfVoters.find((voter) => {
            if (voter.id === this.#currentID) {
                if (voter.status === "") {
                    voter.status = "Not signed yet";
                } else if (voter.status === "Messages signed" || voter.status === "Voted") {
                    this.#statistic["Attempt to vote second time"]++;
                }
            }
            return voter.id === this.#currentID;
        })

        // Checking for same ID on all builetens
        let hasIdenticalBuiletenID = this.#currentPackage.every((builetens) => {
            let cond1 = this.#currentID === builetens.bul1.id;
            let cond2 = this.#currentID === builetens.bul2.id;
            return cond1 || cond2;
        });

        // If not, then +1 to statistic
        if (!hasIdenticalBuiletenID) {
            this.#statistic["Missed correct ID and same ID in all builetens"]++;
            this.#statistic["Voted incorrectly"]++;
            return undefined;
        }

        return this.#decryptMessagesInPackage();
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

        this.#listOfVoters[this.#listOfVoters.findIndex(voter => voter.id === this.#currentID)].status = "Messages decrypted";
        return this.#signTwoBuiletens();
    }

    #signTwoBuiletens() {
        // Retrive two builetens 
        let twoBuiletens = this.#packageObject.package.slice(-1)[0];
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
        twoBuiletens.signPublicKey = this.rsaPublicKey;

        // Change status for voter
        this.#listOfVoters[this.#listOfVoters.findIndex(voter => voter.id === this.#currentID)].status = "Messages signed";

        // Return builetens to voter
        return this.returnBuiletens(twoBuiletens);
    }

    returnBuiletens(builetensPair) {
        return builetensPair;
    }
   
    // Receive final buileten from voter
    receiveFinalBuileten(buileten) {
        // Check for verification
        const isVerified = crypto.verify(
            "sha256",
            Buffer.from(buileten.encryptedVote),
            {
                key: this.rsaPublicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            buileten.signature
        )

        if (isVerified) {
            buileten.vote = crypto.privateDecrypt({
                key: this.#rsaPrivateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            buileten.vote
            );

            // Associate vote with a voter and change their status
            this.#listOfVoters[this.#listOfVoters.findIndex(voter => voter.id === buileten.id)].theirBuileten = buileten;
            this.#listOfVoters[this.#listOfVoters.findIndex(voter => voter.id === buileten.id)].status = "Voted";
        } else {
            this.#statistic["Vote blind sign is incorrect and CVK can not accept and count that vote"]++;
        } 
    }

    #countVotes() {
        let actualVoters = this.#listOfVoters.filter((voter) => {
            return voter.status === "Voted" || voter.status === "Attempt to vote second time";
        });

        this.#statistic["Voted successfully"] = actualVoters.length;

        actualVoters.forEach((voter) => {
            this.listOfCandidates.forEach((candidate) => {
                if (candidate.name === voter.theirBuileten.candidate) {
                    candidate.votes++;
                }
            })
        })
    }

    giveStatistic() {
        return this.#statistic;
    }

    finalResults() {
        this.#countVotes();

        console.log(`
        ~~~~~
        ${this.listOfCandidates[0].name} has scored ${this.listOfCandidates[0].votes}!
        ${this.listOfCandidates[1].name} has scored ${this.listOfCandidates[1].votes}!

        The winner is ${this.listOfCandidates[0].votes >= this.listOfCandidates[1].votes ? this.listOfCandidates[0].name : this.listOfCandidates[1].name}!

        ~~~~~


        Table of participants in voting:
        `)
        this.#listOfVoters.forEach((voter) => {
            console.log(`${voter.id} voted for candidate ${voter.theirBuileten.candidate ? voter.theirBuileten.candidate : ""} with status ${voter.status ? voter.status : "Failed"}`);
        });

        console.log("-----Statistic of voting-----");
        this.#statistic["Ignored voting"] = this.#statistic["Possible voters"] - this.#statistic["Voted incorrectly"] - this.#statistic["Voted successfully"];
        Object.entries(this.#statistic).map(([key, val]) => {
            console.log(`${key}: ${val}`);
        });
    }
}


// Main driver code
function eVoting() {
    let CVK0 = new CVK();

    // Чесні виборці
    let voters = [
        new Voter(
            123456789, 
            ["Yes", "No"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            987654321, 
            ["No", "Yes"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            123465798, 
            ["Yes", "No"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            142536798, 
            ["No", "Yes"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            82365791, 
            ["Yes", "No"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            143675289, 
            ["No", "Yes"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            173946825, 
            ["Yes", "No"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
        new Voter(
            741236985, 
            ["No", "Yes"], 
            ["Twitter new feature is useful", "No, it's not"]
            ),
    ]
    
    // Чесне голосування
    voters.map(voter => {
        voter.formPackage();
        let packageOfVoter = voter.deliverPackage();
        if (packageOfVoter) {
            let pairOfB = CVK0.receivePackage(packageOfVoter);
            if (pairOfB) {
                let signleB = voter.receiveBuiletensPair(pairOfB);
                if (signleB) {
                    CVK0.receiveFinalBuileten(signleB);
                }
            }
        }
    });

    // Шахрайство
    let package1 = voters[0].deliverPackage();
    let pairOfB1 = CVK0.receivePackage(package1); // ЦВК отримує вдруге бюлетені від того ж виборця і це йде в статистику порушень

    let v2 = new SomeVoter(212312, ["No", "Yes"], ["Twitter new feature is useful", "No, it's not"]);   // Неправильно заповнені бюлетені (ID на бюлетенях не однаковий),
                                                                                                        // іде в статистику порушень
    v2.formPackage();
    let package2 = v2.deliverPackage();
    if (package2) {
        let pairOfB2 = CVK0.receivePackage(package2);
        if (pairOfB2) {
            let singleB2 = voter.receiveBuiletensPair(pairOfB2);
            if (singleB2) {
                CVK0.receiveFinalBuileten(singleB2);
            }
        }
    }

    
    
    // testVoter.formPackage();
    // let packageOfVoter = testVoter.deliverPackage();
    // let pairOfB = CVK0.receivePackage(packageOfVoter);
    // let builSingle = testVoter.receiveBuiletensPair(pairOfB);
    // CVK0.receiveFinalBuileten(builSingle);

    // Фінальний результат і підведення підсумків
    CVK0.finalResults();
}


eVoting();

