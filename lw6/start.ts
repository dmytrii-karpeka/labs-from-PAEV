import * as crypto from "crypto";

function getRandomInt(min: number, max: number) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); // The maximum is exclusive and the minimum is inclusive
}

function getRandomString(length: number): string {
    let result           = '';
    const characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for ( let i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

interface BuroArtifact {
    form: string,
    serialNumber: number,
    token: Token,
    login: string,
    password: string
}

interface TokenArtifact {
    status: string,
    token: Token
}

class Buro {
    listOfVoters;
    listOfIDs: number[];
    listOfTokens: TokenArtifact[];
    artifacts: BuroArtifact[];
    constructor(listOfVoters: Voter[]) {
        this.listOfVoters = listOfVoters;
        this.listOfIDs = [];
        this.listOfTokens = [];
        this.artifacts = [];
    }

    IDgeneration() {
        this.listOfVoters.forEach((voter) => {
            this.listOfIDs.push(getRandomInt(10000000, 100000000))
        });
        return this.listOfIDs;
    }

    receiveTokens(tokens: Token[]) {
        tokens.forEach((token) => {
            this.listOfTokens.push({
                status: "free",
                token: token
            })
        })
    }

    receiveForm(form: string) {
        let freeToken = this.listOfTokens.find((tokenart) => {
            return tokenart.status === "free"
        });
        if (freeToken) {
            freeToken.status = "assigned";
            let newArtifact: BuroArtifact = {
                form: form,
                serialNumber: getRandomInt(100000, 1000000),
                token: freeToken.token,
                login: getRandomString(5),
                password: getRandomString(5)
            };
            this.artifacts.push(newArtifact);
        }
    }

    giveArtifact(form: string) {
        return this.artifacts.find((brart) => brart.form === form);
    }
}

interface Token {
    id: number,
    publicKey: crypto.KeyObject
}

interface VKartifact {
    id: number,
    privateKey: crypto.KeyObject,
    token: Token
}

interface Candidate {
    name: string,
    voteFor: number
}

class VK {
    listOfIDs;
    artifacts: VKartifact[];
    candidates;
    constructor(listOfIDs: number[]) {
        this.listOfIDs = listOfIDs;
        this.artifacts = [];
        this.candidates = [
            {
                name: "1",
                voteFor: 0
            },
            {
                name: "2",
                voteFor: 0
            }];
    };


    createTokens() {
        this.listOfIDs.forEach((id) => {
            let keys = this.generateKeys(id);
            let token: Token = {
                id: id,
                publicKey: keys.publicKey
            };
            let artifact: VKartifact = {
                id: id,
                privateKey: keys.privateKey,
                token: token
            }
            this.pushArtifact(artifact);
        })
    }

    generateKeys(id: number) {
        let keyObject = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });
        return keyObject;
    }

    pushArtifact(artifact: VKartifact) {
        this.artifacts.push(artifact)
    }

    sendTokens() {
        let listOfTokens: Token[] = [];
        this.artifacts.forEach((artifact) => {
            listOfTokens.push(artifact.token);
        })
        return listOfTokens;
    }

    processBuileten(buileten: Buileten) {
        let artifact = this.artifacts.find(({id}) => id === buileten.id);
        if (artifact) {
            const decryptedBuileten = crypto.privateDecrypt(
                {
                  key: artifact.privateKey,
                  // In order to decrypt the data, we need to specify the
                  // same hashing function and padding scheme that we used to
                  // encrypt the data in the previous step
                  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  oaepHash: "sha256",
                },
                Buffer.from(buileten.vote));
            let candidate = this.candidates.find(({name}) => name === decryptedBuileten.toString());
            if (candidate) {
                candidate.voteFor++;
            }
        }
    }

    result() {
        this.candidates.sort((a, b) => {
            if (a.voteFor < b.voteFor) return 1;
            if (a.voteFor > b.voteFor) return -1;
            return 0;
        });
        console.log(`The winner of election is ${this.candidates[0].name} with voting for ${this.candidates[0].voteFor}`);

    }
}

class Voter {
    name;
    tokens: BuroArtifact[];
    apps: App[];
    constructor(name: string) {
        this.name = name;
        this.tokens = [];
        this.apps = [];
    }

    receiveToken(tokenArtifact: BuroArtifact) {
        this.tokens.push(tokenArtifact);
    }

    retrieveApp(app: App) {
        this.apps.push(app);
    }

    signIn() {
        let tokenArtifact = this.tokens[0];
        this.apps[0].signIn(tokenArtifact.login, tokenArtifact.password);
    }

    importToken() {
        let tokenArtifact = this.tokens[0];
        this.apps[0].importToken(tokenArtifact.token);
    }

    chooseCandidate() {
        let candidate = getRandomInt(1, 3).toString();
        this.apps[0].putVote(candidate);
    }

    sendVote() {
        return this.apps[0].sendVote();
    }
}

interface Buileten {
    id: number,
    vote: Buffer,
}

class App{
    status: string;
    buileten: Buileten[];
    token: Token[];
    constructor() {
        this.status = "Not signed in";
        this.buileten = [];
        this.token = [];
    }

    signIn(login: string, password: string) {
        this.status = "Signed";
    }

    importToken(token: Token) {
        if (this.status === "Signed") {
            this.status = "Token imported";
            this.token.push(token);
        }
    }

    putVote(candidate: string) {
        this.buileten.push({
            id: this.token[0].id,
            vote: this.#cipherBuileten(candidate, this.token[0].publicKey) 
        })
    }

    sendVote() {
        return this.buileten[0];
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
    ]; 

    let testBuro = new Buro(testListVoters);

    // Buro generate IDs for all possible voters
    let testIDs = testBuro.IDgeneration();

    // Init VK with list of IDs from Buro
    let testVK = new VK(testIDs);

    // VK makes keys for each voter and creates tokens for them
    testVK.createTokens();
    // and sends them to Buro
    testBuro.receiveTokens(testVK.sendTokens())

    // Registration
    testListVoters.forEach((voter) => {
        // Receive form of registration from voter
        testBuro.receiveForm(voter.name);
        // Gives corresponding token, serial number, login and password
        let tokenArtifact = testBuro.giveArtifact(voter.name);
        if (tokenArtifact) {
            // Voter receives said token and metainfo
            voter.receiveToken(tokenArtifact);
            // Voter downloads specific app for voting
            let app = new App();
            voter.retrieveApp(app);
            // Voter signs in
            voter.signIn();
            // Voter imports token
            voter.importToken();
            // Voter chooses candidate to vote
            voter.chooseCandidate();
            // Voter sends vote via app
            let cipheredVote = voter.sendVote();
            // VK proceeds to processing buileten
            testVK.processBuileten(cipheredVote);
        }
    });
    testVK.result();
}

main();