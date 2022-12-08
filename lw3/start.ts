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
    "Attempt to vote without proper registration": number
}

class Buro {
    #register: BuroArtifact[];
    #statistic: Statistic;
    constructor() {
        this.#register = [];
        this.#statistic = {
            "Second voting": 0,
            "Signature violation": 0,
            "Attempt to vote without proper registration": 0
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

interface Candidate {
    name: string,
    votes: number
}

class CVK {
    listOfID: number[];
    #listOfChannels: Channel[];
    #statistic: Statistic;
    #voting: Candidate[];
    constructor(listOfIDs: number[], statistic: Statistic) {
        this.listOfID = listOfIDs;
        this.#listOfChannels = [];
        this.#statistic = statistic;
        this.
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
            this.
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
                return decipheredMessage;
            } else {
                this.#statistic["Second voting"]++;
            }
        } else {
            this.#statistic["Signature violation"]++;
            return "";
        }
        
    }
}

function main() {
    // initialize Buro and Voters
    let testBuro: Buro = new Buro();
    let testVoters: Voter[] = [
        new Voter("Sashko", "Test vote for candidate", 2),
        new Voter("Daryna", "2", 5),
        new Voter("Daryna", "1", 10)
    ]
    // let testVoter: Voter = new Voter("Daryna", 3);
   
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
    let testCVK: CVK = new CVK(testBuro.ListOfID, testBuro.statistic);
    // create CVK public key to cipher
    let pubKey = testCVK.createPublicKey(testVoters[0].gen);
    // voter creates message (buileten) for CVK
    let cipheredMessage = testVoters[0].createMessage(pubKey);
    // CVK deciphers voter's message and their buileten
    let decipherMessage = testCVK.receiveCipheredBuileten(cipheredMessage);
    // let decipheredMessage = testCVK.receiveCipheredBuileten(cipheredMessage);
    console.log(decipherMessage);


}

main();