"use strict";
exports.__esModule = true;
var crypto = require("crypto");
var Voter = /** @class */ (function () {
    function Voter(buileten) {
        var _a = crypto.generateKeyPairSync("rsa", {
            // The standard secure default length for RSA keys is 2048 bits
            modulusLength: 2048
        }), publicKey = _a.publicKey, privateKey = _a.privateKey;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.buileten = buileten;
    }
    Voter.prototype.getPublicKey = function () {
        return this.publicKey;
    };
    Voter.prototype.generateRandomString = function (length) {
        var result = '';
        var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var charactersLength = characters.length;
        for (var i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    };
    return Voter;
}());
function main() {
    console.log("yes");
}
main();
