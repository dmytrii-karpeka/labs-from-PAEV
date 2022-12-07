const elgamal = require('./elgamal.js');
import * as crypto from "crypto";

interface Message {
    ID: number,
    randomID: number,
    buileten: string
}

class Voter {
    readonly name: string;
    readonly gen: number;
    randomID: number;
    #channel: channel;
    #message: Message;
    constructor(name: string, gen: number) {
        this.name = name;
        this.gen = gen;
        this.#channel = elgamal.ElGamal(elgamal.Alphabet, this.gen);
        this.randomID = 0;
        this.#message = {
            ID: 0,
            randomID: 0,
            buileten: ""
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

    createMessage(pubKey: number[]) {


    }
}

interface channel {
    pubKey: number[],
    priKey: number,
    decrypt: Function,
    encrypt: Function
}

interface BuroArtifact {
    readonly name?: string,
    readonly registrationNumber?: number,
    readonly channel: channel
}

interface Statistic {
    "Second voting": number
}

class Buro {
    #register: BuroArtifact[];
    #statistic: Statistic;
    constructor() {
        this.#register = [];
        this.#statistic = {
            "Second voting": 0
        }
    }

    createPublicKey(gen: number) {
        let newChannel: channel = elgamal.ElGamal(elgamal.Alphabet, gen);
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
        let lastChannel: channel = this.#register.slice(-1)[0].channel;
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
}

class CVK {
    listOfID: number[];
    constructor(listOfIDs: number[]) {
        this.listOfID = [];
    }


}

function main() {
    // initialize Buro and Voters
    let testBuro: Buro = new Buro();
    let testVoters: Voter[] = [
        new Voter("Sashko", 2),
        new Voter("Daryna", 5),
        new Voter("Daryna", 10)
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
    // create CVK with list of ID from Buro
    let testCVK: CVK = new CVK(testBuro.ListOfID);

}

main();