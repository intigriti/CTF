function affineEncrypt(x, a, b) {
    return (a * x + b) % 256;
}

function xor(value, key) {
    return value ^ key;
}

function hexToBytes(hex) {
    let bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function reverseString(str) {
    return str.split("").reverse().join("");
}

function keygen() {
    let hexFlag = "9425749445e494332757363353f5d6f50353b79445d7336343270373270366f586365753f546c60336f5"; // The starting string

    let chunks = [hexFlag.slice(0, 14), hexFlag.slice(14, 28), hexFlag.slice(28, 42), hexFlag.slice(42, 56), hexFlag.slice(56, 70), hexFlag.slice(70, 84)];

    let reorderedChunks = [
        chunks[3], // chunk 1
        chunks[5], // chunk 2
        chunks[1], // chunk 3
        chunks[4], // chunk 4
        chunks[2], // chunk 5
        chunks[0], // chunk 6
    ];

    let reversedHex = reverseString(reorderedChunks.join("")); // Join and reverse

    let bytes = hexToBytes(reversedHex);

    let a = 9;
    let b = 7;
    let xorKey = 0x33;

    let transformed = bytes.map((byte) => xor(affineEncrypt(byte, a, b), xorKey));
    return transformed.map((byte) => ("0" + byte.toString(16)).slice(-2)).join("");
}

console.log(keygen());
