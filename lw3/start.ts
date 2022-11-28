console.log("My first ts script");
import { ElGamal, Alphabet } from './elgamal.js';


class Voter {
    readonly name: string;
    readonly messageForBuro: string;
    constructor(name: string, messageForBuro: string) {
        this.name = name;
        this.messageForBuro = messageForBuro;
    }

    #elgamalsedMessage() {
        return ;
    }

    get completedFirstMessage() {
        interface StarterPackForBuro {
            readonly name: string;
            message: unknown; // ciphered by Elgamal algorithm
        }

        let firstMessage: StarterPackForBuro = {
            name: this.name,
            message: this.#elgamalsedMessage()
        }
        return firstMessage;
    }


}

class Buro {
    
}

class CVK {
    
}

function main() {
    let testVoter: Voter = new Voter("Daryna", "Hi, please give me my ID");
}