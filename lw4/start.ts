import * as crypto from "crypto";


interface Register {
    previous: Array<Buffer|string>,
    result: Array<Buffer|string>,
    randomString: string
}

class Voter {
    publicKey;
    privateKey;

    name: string;
    buileten: string;

    register: Register[];
    constructor(name: string, buileten: string) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: 2048,
          });
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.name = name;
        this.buileten = this.name + " " + buileten;
        this.register = [];
    }

    getPublicKey() {
        return this.publicKey;
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
            let lastResult = lastDataObject.result;
            let newResult: Register = {
                previous: lastResult,
                result: [],
                randomString: randomString
            }
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
                
                newResult.result.push(encryptedData);
            })

            this.register.push(newResult);
            console.log(this.register);
        }

        
    }

    decipherMessage() {
        let testDec: Register = this.register.slice(-1)[0];
        let deciphered: string[] = [];
        testDec.result.forEach((string) => {
            const decryptedData = crypto.privateDecrypt(
                {
                  key: this.privateKey,
                  // In order to decrypt the data, we need to specify the
                  // same hashing function and padding scheme that we used to
                  // encrypt the data in the previous step
                  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  oaepHash: "sha256",
                },
                Buffer.from(string)
              );
            deciphered.push(decryptedData.toString());
        })

        console.log(deciphered);
    }
}

function main() {
    let testVoter: Voter = new Voter("Dima", "Against");
    testVoter.cipherWithPublicKey(testVoter.getPublicKey(), "");
    testVoter.decipherMessage();
}

main();