import * as crypto from "crypto";


interface Register {
    previous: Array<Buffer|string>,
    result: Array<Buffer|string>,
    randomString: string
}

interface MessageToA {
    
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

    // decipherMessage() {
    //     let testDec: Register = this.register.slice(-1)[0];
    //     let deciphered: string[] = [];
    //     testDec.result.forEach((string) => {
    //         const decryptedData = crypto.privateDecrypt(
    //             {
    //               key: this.privateKey,
    //               // In order to decrypt the data, we need to specify the
    //               // same hashing function and padding scheme that we used to
    //               // encrypt the data in the previous step
    //               padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    //               oaepHash: "sha256",
    //             },
    //             Buffer.from(string)
    //           );
    //         deciphered.push(decryptedData.toString());
    //     })

        // console.log(deciphered);
    // }
}

function main() {
    // new Voter("A", "For");
    // new Voter("B", "Against");
    // new Voter("C", "For");
    // new Voter("D", "For");
    const basebin = 1024;

    let voters: Voter[] = [
        new Voter("A", "For", basebin*4),
        new Voter("B", "Against", basebin*3),
        new Voter("C", "For", basebin*2),
        new Voter("D", "For", basebin)
    ];

    // everybody cipher buileten+rS(random string) with open key
    voters.forEach((voter: Voter) => {
        voter.cipherWithPublicKey(voters[3].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[2].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[1].getShortPublicKey(), "");
        voter.cipherWithPublicKey(voters[0].getShortPublicKey(), "");
    });

    // voters.forEach((voter: Voter, index) => {
    //     voter.generateNewPairOfKeys(basebin*(8 - index))
    // });

    voters.forEach((voter: Voter) => {
        voter.cipherWithPublicKey(voters[3].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[2].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[1].getLongPublicKey(), voter.generateRandomString(5));
        voter.cipherWithPublicKey(voters[0].getLongPublicKey(), voter.generateRandomString(5));
    });

    console.log(voters[0].completedMessage(), voters[0].logReg());

    // test drive

}

main();