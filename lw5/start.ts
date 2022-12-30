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
    privateKey2: crypto.KeyObject
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
                    privateKey2: obj2.privateKey
                }
            );
        });
    }

    
}

interface Message {
    buileten: string|Buffer,
    theirId: number,
    signature: string|Buffer,
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

        console.log(this.voteFor.id);
        console.log(this.buileten1);
        console.log(this.buileten2);
    }

    formMessage(publicKeyToCipher: crypto.KeyObject, buileten: string) {
        let cipheredMessage = this.cipherBuileten(buileten, publicKeyToCipher);
        let message: Message = {
            buileten: cipheredMessage,
            theirId: this.id,
            signature: this.signBuileten(cipheredMessage),
            publicKey: this.publicKey
        }
        return message
    }

    cipherBuileten(buileten: string, publicKeyToCipher: crypto.KeyObject) {
        const data = buileten;
        const encryptedData = crypto.publicEncrypt(
        {
            key: publicKeyToCipher,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(data)
        );
        return data;
    }

    signBuileten(buileten: string) {
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
        new Voter("Daryna")
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

    // Initialization of CVK
    let testCVK = new CVK(testListVoters, testCandidates);
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
    testListVoters[0].separateId();

    // each voter ciphers two builetens with public key from CVK


    console.log(testListVoters[0].name, testListVoters[0].id);
    console.log(testCandidates[0].name, testCandidates[0].id);
}

main();