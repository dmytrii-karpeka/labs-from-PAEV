const elgamal = require('./elgamal.js');
import * as crypto from "crypto";

interface Message {
    ID: number,
    randomID: number,
    buileten: string,
    signature: Buffer,
    publicKey: crypto.KeyObject
}

class Voter {
    readonly name: string;
    readonly gen: number;
    readonly privateKey: crypto.KeyObject
    randomID: number;
    #channel: Channel;
    #message: Message;
    constructor(name: string, message: string, gen: number) {
        this.name = name;
        this.gen = gen;
        this.#channel = elgamal.ElGamal(elgamal.Alphabet, this.gen);
        this.randomID = 0;
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: 2048,
          });
        this.privateKey = privateKey;
        this.#message = {
            ID: 0,
            randomID: 0,
            buileten: message,
            signature: Buffer.from(""),
            publicKey: publicKey
        }
    }

    get voterGen() {
        return this.gen;
    }

    cipherMessage(m: string, pubKey: number[]) {
        let ciphered: string = this.#channel.encrypt(m, pubKey);
        return ciphered;
    }

    receiveRandomID(id: number) {
        this.randomID = id;
    }

    signBuileten(buileten: string) {
        const verifiableData = buileten;
        const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
            key: this.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          });
        
        return signature;
    }

    createMessage(pubKey: number[]) {
        this.#message.ID = crypto.randomInt(100000, 1000000);
        this.#message.randomID = this.randomID;
        this.#message.buileten = this.cipherMessage(this.#message.buileten, pubKey);
        this.#message.signature = this.signBuileten(this.#message.buileten);
        return this.#message;
    }
}

interface Channel {
    pubKey: number[],
    priKey: number,
    decrypt: Function,
    encrypt: Function
}

interface BuroArtifact {
    readonly name?: string,
    readonly registrationNumber?: number,
    readonly channel: Channel
}

interface Statistic {
    "Second voting": number,
    "Signature violation": number,
    "Attempt to vote without proper registration": number,
    "Not unique ID": number
}

class Buro {
    #register: BuroArtifact[];
    #statistic: Statistic;
    constructor() {
        this.#register = [];
        this.#statistic = {
            "Second voting": 0,
            "Signature violation": 0,
            "Attempt to vote without proper registration": 0,
            "Not unique ID": 0
        }
    }

    createPublicKey(gen: number) {
        let newChannel: Channel = elgamal.ElGamal(elgamal.Alphabet, gen);
        this.#register.push(
            {
                name: undefined,
                registrationNumber: undefined,
                channel: newChannel
            }
        )
        return newChannel.pubKey;
    }

    receiveCipheredMessage(m: string) {
        // decipher message using last channel of communication
        let lastChannel: Channel = this.#register.slice(-1)[0].channel;
        let decipheredMessage: string = lastChannel.decrypt(m);
        if (this.#register.find((buroArt: BuroArtifact) => {
            return buroArt.name === decipheredMessage;
        })) {
            console.log("Attempt to vote second time");
            this.#statistic["Second voting"]++;
            return 0;
        } else {
            let newArtifact: BuroArtifact = {
                name: decipheredMessage,
                registrationNumber: crypto.randomInt(100000, 1000000000000),
                channel: lastChannel
            }
            this.#register[this.#register.length - 1] = newArtifact;
            if (newArtifact.registrationNumber) {
                return newArtifact.registrationNumber
            } else {
                return 0;
            }
            
        }
    }

    get ListOfID() {
        let listOfID: number[] = []; 
        this.#register.forEach((buroArt) => {
            let ID  = buroArt.registrationNumber;
            if (ID) {
                listOfID.push(ID);
            }
            
        })
        return listOfID;
    }

    get statistic() {
        return this.#statistic;
    }
}

interface Candidates {
    [name: string]: number
}

interface finalVote {
    id: number,
    buileten: string
}

class CVK {
    listOfID: number[];
    #listOfChannels: Channel[];
    #statistic: Statistic;
    #voting: Candidates;
    #finalList: finalVote[];
    constructor(listOfIDs: number[], statistic: Statistic, candidateNames: string[]) {
        this.listOfID = listOfIDs;
        this.#listOfChannels = [];
        this.#statistic = statistic;
        this.#voting = {};
        candidateNames.map((candidateName) => this.#voting[candidateName] = 0)
        this.#finalList = [];
    }

    createPublicKey(gen: number) {
        let newChannel: Channel = elgamal.ElGamal(elgamal.Alphabet, gen);
        this.#listOfChannels.push(newChannel);
        return newChannel.pubKey;
    }

    verification(message: Message) {
        // check signature for violation
        const isVerified: boolean = crypto.verify(
            "sha256",
            Buffer.from(message.buileten),
            {
              key: message.publicKey,
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            message.signature
          );
        return isVerified;
    }

    checkForUniqueID(message: Message) {
        let uniqueness = this.listOfID.includes(message.randomID);

        // console.log("this id is unique: ", uniqueness);
        if (!uniqueness) {
            console.log("Attempt to vote without proper registration");
            this.#statistic["Attempt to vote without proper registration"]++;
        } else {
            const index: number = this.listOfID.indexOf(message.randomID);
            this.listOfID.splice(index, 1);
        }

        return uniqueness;
    }

    receiveCipheredBuileten(message: Message) {
        let verified: boolean = this.verification(message);
        let unique: boolean = this.checkForUniqueID(message);
        if (verified) {
            if (unique) {
                let lastChannel: Channel = this.#listOfChannels.slice(-1)[0];
                let decipheredMessage: string = lastChannel.decrypt(message.buileten);
                this.#finalList.push({
                    id: message.ID,
                    buileten: decipheredMessage
                });
                this.#voting[decipheredMessage]++;
            } else {
                this.#statistic["Not unique ID"]++;
            }
        } else {
            this.#statistic["Signature violation"]++;
        }
    }

    retrieveResults() {
        Object.entries(this.#voting).forEach(([candidate, votes]) => {
            console.log(`${candidate} has scored ${votes} votes`);
        })
        let votingSorted = Object.entries(this.#voting).sort(([name1, vote1], [name2, vote2]) => vote2 - vote1);
        console.log("The winner is ", votingSorted[0][0], " with votes of ", votingSorted[0][1]);

        console.log("Table of participants: ");
        this.#finalList.forEach((finalVote) => {
            console.log("Participant with ID", finalVote.id, "voted for", finalVote.buileten);
        })

        console.log("Violations fixed during voting process:")
        Object.entries(this.#statistic).forEach(([name, violations]) => {
            console.log(name, ":", violations);
        })
    }
}

function main() {
    // initialize Buro and Voters
    let testBuro: Buro = new Buro();
    let testVoters: Voter[] = [
        new Voter("Sashko", "Option1", 2),
        new Voter("Sashko", "Option2", 3), // second time voting
        new Voter("Daryna", "Option1", 5),
        new Voter("Alex", "Option2", 10),
        new Voter("Antin", "Option1", 17),
        new Voter("Dmytrii", "Option2", 19),
        new Voter("Olena", "Option2", 23),
        new Voter("Artem", "Option2", 61),
        new Voter("Lidiia", "Option1", 31),
        new Voter("Sophia", "Option2", 37)
    ]
   
    testVoters.forEach((testVoter) => {
        // create gen in voter
        let voterGen: number = testVoter.voterGen;
        // give gen to BR to create public key
        let pubKey: number[] = testBuro.createPublicKey(voterGen);
        // return public key from BR to Voter to cipher
        let cipheredMessage = testVoter.cipherMessage(testVoter.name, pubKey);
        // console.log(typeof cipheredMessage);
        // give ciphered message to Buro
        let lastRegistrationNumber: number = testBuro.receiveCipheredMessage(cipheredMessage);
        // console.log(lastRegistrationNumber);
        // voter gets his generated ID for voting
        testVoter.receiveRandomID(lastRegistrationNumber);
    });

    // create CVK with list of ID from Buro and their statistic of violations
    let testCVK: CVK = new CVK(testBuro.ListOfID, testBuro.statistic, ["Option1", "Option2"]);
    
    testVoters.forEach((testVoter) => {
        // create CVK public key to cipher
        let pubKey = testCVK.createPublicKey(testVoter.gen);
        // voter creates message (buileten) for CVK
        let cipheredMessage = testVoter.createMessage(pubKey);
        // CVK deciphers voter's message and their buileten
        testCVK.receiveCipheredBuileten(cipheredMessage);
    });

    testCVK.retrieveResults();
}

main();