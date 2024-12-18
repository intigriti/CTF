function affineDecrypt(x, a_inv, b) {
    return (a_inv * (x - b + 256)) % 256;
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

function bytesToHexString(bytes) {
    return bytes.map((byte) => ("0" + byte.toString(16)).slice(-2)).join("");
}

function solve() {
    let a_inv = 57; // Modular inverse of 9 mod 256
    let b = 7;
    let xorKey = 0x33;

    // The encoded string (output from keygen)
    let encodedHex = "abf6c8abb5daabc8ab69d7846def17b19c6dae843a6dd7e1b1173ae16db184e0b86dd7c5843ae8dee15f";

    // Step 1: Convert hex to bytes
    let bytes = hexToBytes(encodedHex);

    // Step 2: XOR with 0x33 and affine decryption
    let decryptedBytes = bytes.map((byte) => affineDecrypt(xor(byte, xorKey), a_inv, b));

    // Convert bytes back to hex for further processing or output
    let decryptedHex = bytesToHexString(decryptedBytes);

    console.log("Decrypted Hex:", decryptedHex);
}

solve();
