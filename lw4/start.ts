import * as crypto from "crypto";


interface Register {
    previous: Array<Buffer|string>,
    result: Array<Buffer|string>,
    randomString: string
}

interface messageObject {
    messages: string,
    sign: Buffer,
    key: crypto.KeyObject
}

class Voter {
    shortKey;
    shortPrivateKey;

    longKey;
    longPrivateKey;

    name: string;
    buileten: string;

    register: Register[];
    constructor(name: string, buileten: string, beginLength: number) {
        const shortKeysObject = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: beginLength,
          });
        this.shortKey = shortKeysObject.publicKey;
        this.shortPrivateKey = shortKeysObject.privateKey;

        const longKeysObject = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: beginLength+(1024*4),
          });
        this.longKey = longKeysObject.publicKey;
        this.longPrivateKey = longKeysObject.privateKey;
        console.log(beginLength+(1024*4))

        this.name = name;
        this.buileten = this.name + " " + buileten;
        this.register = [];
    }

    getShortPublicKey() {
        return this.shortKey;
    }

    getLongPublicKey() {
        return this.longKey;
    }

    generateRandomString(length: number): string {
        let result           = '';
        const characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const charactersLength = characters.length;
        for ( let i = 0; i < length; i++ ) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }

    cipherWithPublicKey(pubKey: crypto.KeyObject, randomString: string) {
        if (this.register.length === 0) {
            console.log("encryption1")
            const randomString = this.generateRandomString(5);
            this.register.push(
                {
                    previous: [this.buileten],
                    result: [this.buileten, randomString],
                    randomString: randomString
                }
            );
        }

        if (this.register.length !== 0) {
            console.log("encryption2")
            let lastDataObject: Register = this.register.slice(-1)[0];
            let lastResult = [...lastDataObject.result];

            if (randomString.length !== 0) {
                lastResult.push(randomString);
            }
            
            let newRegister: Register = {
                previous: lastResult,
                result: [],
                randomString: randomString
            };

            console.log(lastResult);

            lastResult.forEach((string) => {
                const encryptedData = crypto.publicEncrypt(
                    {
                      key: pubKey,
                      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                      oaepHash: "sha256",
                    },
                    // We convert the data string to a buffer using `Buffer.from`
                    Buffer.from(string)
                  );
                newRegister.result.push(encryptedData);
            })

            this.register.push(newRegister);
            // console.log(this.register);
        } 
    }

    completedMessage() {
        return this.register.slice(-1)[0].result;
    }

    logReg() {
        return this.register;
    }

    decipherMessagesWithLongKey(messages: (String|Buffer)[][]) {
        let partDecipheredMessages: (String|Buffer)[][] = [];
        messages.forEach((message) => {
            let partDecipheredMessage: (String|Buffer)[] = [];
            message.forEach((singleString) => {
                const decryptedString = crypto.privateDecrypt(
                    {
                      key: this.longPrivateKey,
                      // In order to decrypt the data, we need to specify the
                      // same hashing function and padding scheme that we used to
                      // encrypt the data in the previous step
                      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                      oaepHash: "sha256",
                    },
                    Buffer.from(singleString)
                  );
                
                const convertedString = decryptedString.toString();
                if (convertedString.length !== 5) {
                    partDecipheredMessage.push(decryptedString);
                }
            });
            partDecipheredMessages.push(partDecipheredMessage);
        });
        return partDecipheredMessages;
    }

    decipherMessagesWithShortKey(messages: (String|Buffer)[][]) {
        let partDecipheredMessages: (String|Buffer)[][] = [];
        messages.forEach((message) => {
            let partDecipheredMessage: (String|Buffer)[] = [];
            message.forEach((singleString) => {
                const decryptedString = crypto.privateDecrypt(
                    {
                      key: this.shortPrivateKey,
                      // In order to decrypt the data, we need to specify the
                      // same hashing function and padding scheme that we used to
                      // encrypt the data in the previous step
                      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                      oaepHash: "sha256",
                    },
                    Buffer.from(singleString)
                  );
                
                const convertedString = decryptedString.toString();
                if (convertedString.length !== 5) {
                    partDecipheredMessage.push(decryptedString);
                }
            });
            partDecipheredMessages.push(partDecipheredMessage);
        });
        return partDecipheredMessages;
    }

    shuffle(messages: (String|Buffer)[][]) {
        let currentIndex = messages.length,  randomIndex;

        // While there remain elements to shuffle.
        while (currentIndex != 0) {

            // Pick a remaining element.
            randomIndex = Math.floor(Math.random() * currentIndex);
            currentIndex--;

            // And swap it with the current element.
            [messages[currentIndex], messages[randomIndex]] = [
            messages[randomIndex], messages[currentIndex]];
        }

        return messages;
    }

    sign(messages: (String|Buffer)[][]) {
        let shuffeledMessages = this.shuffle(messages);
        let stringifiedMessages = JSON.stringify(shuffeledMessages);

        // The signature method takes the data we want to sign, the
        // hashing algorithm, and the padding scheme, and generates
        // a signature in the form of bytes
        const signature = crypto.sign("sha256", Buffer.from(stringifiedMessages), {
        key: this.longPrivateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        });

        let formedObject: messageObject = {
            messages: stringifiedMessages,
            sign: signature,
            key: this.longKey
        };

        return formedObject;
    }

    verify(formedObject: messageObject) {
        let newMessage = [];
        const isVerified = crypto.verify(
            "sha256",
            Buffer.from(formedObject.messages),
            {
              key: formedObject.key,
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            formedObject.sign
          );

        if (isVerified) {
            // console.log("Verified");
            newMessage = JSON.parse(formedObject.messages);
            return newMessage;
        }
    }

    // TODO
    findVote(decipheredMessages: (string|Buffer)[][]) {
        return decipheredMessages.flat().map(message => message.toString()).includes(this.buileten);
    }

    // TODO
    countVotes() {
        ;
    }


}

function main() {
    // new Voter("A", "For");
    // new Voter("B", "Against");
    // new Voter("C", "For");
    // new Voter("D", "For");
    const basebin = 1024;

    let voters: Voter[] = [
        new Voter("A", "Support", basebin*4),
        new Voter("B", "Against", basebin*3),
        new Voter("C", "Support", basebin*2),
        new Voter("D", "Support", basebin)
    ];

    // everybody cipher buileten+rS(random string) with open key
    voters.forEach((voter: Voter) => {
        voter.cipherWithPublicKey(voters[3].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[2].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[1].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[0].getShortPublicKey(), "");
    });

    // Second iteration with longer key
    voters.forEach((voter: Voter) => {
        voter.cipherWithPublicKey(voters[3].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[2].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[1].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[0].getLongPublicKey(), voter.generateRandomString(5));
    });

    // Get completed messages from all voters
    let messages: (String|Buffer)[][] = [];
    voters.forEach((voter) => {
        let message = voter.completedMessage();
        messages.push(message);
    });

    // Deciphering of messages and deleting random strings
    let newMessages = messages;
    voters.forEach((voter) => {
        let decipheredM = voter.decipherMessagesWithLongKey(newMessages);
        let shuffledM = voter.shuffle(decipheredM);
        newMessages = shuffledM;
    });

    // Deciphering for second time and deleting random strings, validating and signing, deleting signature
    let checkedM0 = voters[0].decipherMessagesWithShortKey(newMessages);
    let checkedObject0 = voters[0].sign(checkedM0);

    let validaded1 = voters[1].verify(checkedObject0);
    let checkedM1 = voters[1].decipherMessagesWithShortKey(validaded1);
    let checkedObject1 = voters[1].sign(checkedM1);

    let validaded2 = voters[2].verify(checkedObject1);
    let checkedM2 = voters[2].decipherMessagesWithShortKey(validaded2);
    let checkedObject2 = voters[2].sign(checkedM2);

    let validaded3 = voters[3].verify(checkedObject2);
    let checkedM3 = voters[3].decipherMessagesWithShortKey(validaded3);
    let checkedObject3 = voters[3].sign(checkedM3);


    let finalVerified0 = voters[0].verify(checkedObject3);
    let finalVerified1 = voters[1].verify(checkedObject3);
    let finalVerified2 = voters[2].verify(checkedObject3);
    let finalVerified3 = voters[3].verify(checkedObject3);
    // Check whether everyone agree with final deciphered list of builetens
    // voters.every(voter => voter.findVote())

    

    // console.log(newMessages[0]);
    newMessages.forEach((message) => {
        message.forEach((singleString) => {
            console.log(singleString.toString());
        })
    })
    // test drive

}

main();