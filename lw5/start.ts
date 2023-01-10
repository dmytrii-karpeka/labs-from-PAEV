import * as crypto from "crypto";

function getRandomInt(min: number, max: number) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); // The maximum is exclusive and the minimum is inclusive
  }

interface Candidate {
    name: string,
    id: number,
    votesFor: number
}

interface CVKartifact {
    voter: Voter,
    publicKey1: crypto.KeyObject,
    privateKey1: crypto.KeyObject,
    publicKey2: crypto.KeyObject,
    privateKey2: crypto.KeyObject,
    part1: Buffer,
    part2: Buffer,
    wholeBuileten: String
}

class CVK {
    listOfVoters;
    candidates;
    artifacts: CVKartifact[];
    constructor(listOfVoters: Voter[], candidates: Candidate[]) {
        this.listOfVoters = listOfVoters;
        this.candidates = candidates;
        this.artifacts = [];
    }

    generateID() {
        this.candidates.forEach((candidate) => {
            candidate.id = getRandomInt(10000000, 40000000);
            console.log("Candidate id is " + candidate.id);
        });

        this.listOfVoters.forEach((voter) => {
            voter.id = getRandomInt(10000000, 40000000);
        });
    }

    createPublicKeys() {
        this.listOfVoters.forEach((voter) => {
            let obj1 = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048,
            });
            let obj2 = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048,
            });

            this.artifacts.push(
                {
                    voter: voter,
                    publicKey1: obj1.publicKey,
                    privateKey1: obj1.privateKey,
                    publicKey2: obj2.publicKey,
                    privateKey2: obj2.privateKey,
                    part1: Buffer.from(""),
                    part2: Buffer.from(""),
                    wholeBuileten: ""
                }
            );

        });
    }

    givePublicKeys(voter: Voter) {
        let artifact = this.artifacts.find((artifact) => {
            return artifact.voter === voter;
        });
        if (artifact) {
            let publicKeys = {
                pKey1: artifact.publicKey1,
                pKey2: artifact.publicKey2
            }
            return publicKeys;
        }
    }

    receiveTwoParts(part1: Output[], part2: Output[]) {
        this.artifacts.forEach((artifact) => {
            let voterPart1 = part1.find((singleOutput) => singleOutput.id === artifact.voter.id);
            let voterPart2 = part2.find((singleOutput) => singleOutput.id === artifact.voter.id);
            if (voterPart1 && voterPart2) {
                artifact.part1 = Buffer.from(voterPart1.cipheredBuileten);
                artifact.part2 = Buffer.from(voterPart2.cipheredBuileten);
            }
        })
    }

    decipherAllBuiletens() {
        this.artifacts.forEach((artifact) => {
            const decryptedString1 = crypto.privateDecrypt(
                {
                  key: artifact.privateKey1,
                  // In order to decrypt the data, we need to specify the
                  // same hashing function and padding scheme that we used to
                  // encrypt the data in the previous step
                  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  oaepHash: "sha256",
                },
                Buffer.from(artifact.part1));
            const decryptedString2 = crypto.privateDecrypt(
                {
                  key: artifact.privateKey2,
                  // In order to decrypt the data, we need to specify the
                  // same hashing function and padding scheme that we used to
                  // encrypt the data in the previous step
                  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  oaepHash: "sha256",
                },
                Buffer.from(artifact.part2));
            
            artifact.wholeBuileten = decryptedString1.toString() + decryptedString2.toString();
        });
    }

    results() {
        this.artifacts.forEach((artifact) => {
            let candidate = this.candidates.find((candidate) => candidate.id.toString() === artifact.wholeBuileten);
            if (candidate) {
                candidate.votesFor++;
            }
        });

        this.candidates.sort((a, b) => {
            if (a.votesFor < b.votesFor) return -1;
            if (a.votesFor > b.votesFor) return 1;
            return 0;
        })

        console.log(`The winner of election is ${this.candidates[0].name} with id ${this.candidates[0].id} with voting for ${this.candidates[0].votesFor}`);

        this.artifacts.forEach((artifact) => {
            console.log(`${artifact.voter.id} voted for candidate ${artifact.wholeBuileten}`);
        })


    }
}

interface VKartifact {
    id: number,
    cipheredBuileten: string|Buffer,
    status: string
}

interface Output {
    id: number,
    cipheredBuileten: string|Buffer
}

class VK {
    register: VKartifact[];
    constructor() {
        this.register = [];
    }

    receiveMessage(message: Message) {
        if (this.#validateSignature(message.buileten, message.signature, message.publicKey)) {
            if (!this.register.find((vkart) => vkart.id === message.theirId)) {
                this.register.push({
                    id: message.theirId,
                    cipheredBuileten: message.buileten,
                    status: "received"
                });
            }
        }
        // console.log(this.register);
    }

    publishIDandBuiletens() {
        let output: Output[] = [];
        this.register.forEach((vkart) => {
            output.push({
                id: vkart.id,
                cipheredBuileten: vkart.cipheredBuileten
            })
        })
        return output;
    }

    #validateSignature(data: String|Buffer, signature: Buffer, pKey: crypto.KeyObject) {
        const isVerified = crypto.verify(
            "sha256",
            Buffer.from(data),
            {
              key: pKey,
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            signature
          );
        return isVerified;
    }
}

interface Message {
    buileten: string|Buffer,
    theirId: number,
    signature: Buffer,
    publicKey: crypto.KeyObject
}

class Voter {
    name;
    id: number;
    voteFor: Candidate;
    buileten1: string;
    buileten2: string;
    // Keys for signing
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
    // Public keys for ciphering bul1 and bul2
    constructor(name: string) {
        this.name = name;
        this.id = 0;
        this.voteFor = {
            name: "",
            votesFor: 0,
            id: 0
        };
        this.buileten1 = "";
        this.buileten2 = "";

        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: 2048,
          });
        
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    };

    separateId() {
        this.buileten1 = this.voteFor.id.toString();
        this.buileten2 = this.buileten1.substring(this.buileten1.length/2);
        this.buileten1 = this.buileten1.substring(0, this.buileten1.length/2);
    }

    formMessage(publicKeyToCipher: crypto.KeyObject, buileten: string) {
        let cipheredMessage = this.#cipherBuileten(buileten, publicKeyToCipher);
        let message: Message = {
            buileten: cipheredMessage,
            theirId: this.id,
            signature: this.#signBuileten(cipheredMessage),
            publicKey: this.publicKey
        }
        return message
    }

    #cipherBuileten(buileten: string, publicKeyToCipher: crypto.KeyObject) {
        const data = buileten;
        const encryptedData = crypto.publicEncrypt(
        {
            key: publicKeyToCipher,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(data)
        );
        return encryptedData;
    }

    #signBuileten(buileten: string|Buffer) {
        const verifiableData = buileten;
        const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
            key: this.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          });
        return signature;
    }


}



function main() {
    let testListVoters: Voter[] = [
        new Voter("Maria"),
        new Voter("Daryna"),
        new Voter("Dima"),
        new Voter("Lana"),
        new Voter("Ora"),
        new Voter("Vera"),
        new Voter("Lama"),
        new Voter("Dana"),
        new Voter("Egor"),
    ] 

    let testCandidates: Candidate[] = [
        {
            name: "1",
            id: 0,
            votesFor: 0
        },
        {
            name: "2",
            id: 0,
            votesFor: 0
        }
    ]

    // Initialization of CVK and VKs
    let testCVK = new CVK(testListVoters, testCandidates);
    let testVK1 = new VK();
    let testVK2 = new VK();
    // generating of ID for Voters and Candidates
    testCVK.generateID();

    // voter choose between candidates
    testListVoters.forEach((voter, index) => {
        if (index % 2 === 0) {
            voter.voteFor = testCandidates[0];
        } else {
            voter.voteFor = testCandidates[1];
        }
    });

    // each voter divide candidate's id into two separate builetens
    testListVoters.forEach((voter) => voter.separateId());

    // CVK gives creates public keys for all voters
    testCVK.createPublicKeys();

    // Each voter receives their public key and proceed to ciphering their builetens
    testListVoters.forEach((voter) => {
        let pubKeys = testCVK.givePublicKeys(voter);
        if (pubKeys) {
            let message1 = voter.formMessage(pubKeys.pKey1, voter.buileten1);
            let message2 = voter.formMessage(pubKeys.pKey2, voter.buileten2);

            console.log(message1);
            console.log(message2);
            // VKs receiving their corresponding builetens
            testVK1.receiveMessage(message1);
            testVK2.receiveMessage(message2);
        }
    })

    // VKs publish IDs and builetens
    let part1 = testVK1.publishIDandBuiletens();
    let part2 = testVK2.publishIDandBuiletens();

    // CVK receives two parts of builetens from VKs
    testCVK.receiveTwoParts(part1, part2);

    // CVK deciphers all builetens
    testCVK.decipherAllBuiletens();

    // CVK gives  results
    testCVK.results();
}

main();