#include <iostream>
#include <string>
#include <bitset>
#include <stdexcept>

using namespace std;

const int SBox[8][4][16] = {
        // S-box 1
        {
                {14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7},
                {0,  15, 7,  4,  14, 2,  13, 1,  10, 6, 12, 11, 9,  5,  3,  8},
                {4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0},
                {15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0, 6,  13}
        },

        // S-box 2
        {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7,        12, 0,  5, 14, 9}
        },

        // S-box 3
        {
                {10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8},
                {13, 7,  0,  9,  3,  4,  6,  10, 2,  8, 5,  14, 12, 11, 15, 1},
                {13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7},
                {1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5, 2,  12}
        },

        // S-box 4
        {
                {7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15},
                {13, 8,  11, 5,  6,  15, 0,  3,  4,  7, 2,  12, 1,  10, 14, 9},
                {10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4},
                {3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14}
        },

        // S-box 5
        {
                {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9},
                {14, 11, 2,  12, 4,  7,  13, 1,  5,  0, 15, 10, 3,  9,  8,  6},
                {4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14},
                {11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3}
        },

        // S-box 6
        {
                {12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11},
                {10, 15, 4,  2,  7,  12, 9,  5,  6,  1, 13, 14, 0,  11, 3,  8},
                {9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6},
                {4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0, 8,  13}
        },

        // S-box 7
        {
                {4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1},
                {13, 0,  11, 7,  4,  9,  1,  10, 14, 3, 5,  12, 2,  15, 8,  6},
                {1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2},
                {6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2, 3,  12}
        },

        // S-box 8
        {
                {13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7},
                {1,  15, 13, 8,  10, 3,  7,  4,  12, 5, 6,  11, 0,  14, 9,  2},
                {7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8},
                {2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5, 6,  11}
        }
};

const int PC1[56] = { // this used to decide which bits to use from the original key
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
};

const int PC2[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

const int rotationSchedule[16] = { // this is used to decide how many bits to rotate the key by
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
}; // The array is 16 elements long because there are 16 rounds. The chosen values are arbitrary.

const int IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};

const int EBox[48] = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
};


class DES {
private:
    string key;
    bitset<64> keyAsBinary;
    bitset<56> reducedKey;
    bitset<28> leftHalf, rightHalf;
    bitset<48> roundKeys[16];

    // Encryption
    bitset<64> encryptedBits;

    // Input
    bitset<64> plaintextBits;


    static bitset<48> expand(const bitset<32> &half) {
        bitset<48> expandedHalf;

        for (int i = 0; i < 48; i++) {
            expandedHalf[i] = half[EBox[i] - 1];
        }

        return expandedHalf;
    }

    bitset<64> startEncryptionRounds() {
        bitset<64> ciphertextBits = plaintextBits;
        bitset<32> leftHalf, rightHalf, tempHalf;
        bitset<64> combinedHalves;

        for (int i = 0; i < 32; i++) {
            leftHalf[i] = ciphertextBits[i];
            rightHalf[i] = ciphertextBits[i + 32];
        }

        bitset<48> expandedRightHalf = expand(rightHalf);
        bitset<48> expandedLeftHalf = expand(leftHalf);

        for (int round = 0; round < 16; round++) {
            // XOR the expanded right half with the round key
            bitset<48> xoredRightHalf = expandedRightHalf ^ roundKeys[round];

            // Substitution step
            bitset<6> blocks[8];
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 6; j++) {
                    blocks[i][j] = xoredRightHalf[i * 6 + j];
                }
            }

            bitset<32> substitutedBlocks;
            for (int i = 0; i < 8; i++) {
                int row = (blocks[i][0] << 1) | blocks[i][5];
                int column = (blocks[i] >> 1).to_ulong();
                int sBoxValue = SBox[i][row][column];
                bitset<4> sBoxOutput(sBoxValue);

                for (int j = 0; j < 4; j++) {
                    substitutedBlocks[i * 4 + j] = sBoxOutput[j];
                }
            }

            // Permutation step
            bitset<32> permutedBlocks;
            for (int i = 0; i < 32; i++) {
                permutedBlocks[i] = substitutedBlocks[IP[i] - 1];
            }

            // Set the left half to the right half - swap
            tempHalf = leftHalf;
            leftHalf = rightHalf;
            rightHalf = tempHalf ^ permutedBlocks;

            // Combine the halves
            combinedHalves = (leftHalf.to_ullong() << 32) | rightHalf.to_ullong();
        }

        return combinedHalves;
    }


    bitset<64> applyIPToPlaintext(const bitset<64> &plaintextBits) {
        bitset<64> permutedPlaintext;

        for (int i = 0; i < 64; i++) {
            permutedPlaintext[i] = plaintextBits[IP[i] - 1];
        }

        return permutedPlaintext;
    }

    void rotateAndPermutate() {
        bitset<48> roundKeys[16];

        for (int round = 0; round < 16; round++) {
            leftHalf = leftHalf << rotationSchedule[round] | leftHalf >> (28 - rotationSchedule[round]);
            rightHalf = rightHalf << rotationSchedule[round] | rightHalf >> (28 - rotationSchedule[round]);

            // Combine the halves
            bitset<56> combinedKey = (leftHalf.to_ullong() << 28) | rightHalf.to_ullong();
            roundKeys[round] = applyPC2(combinedKey); // Apply PC-2 permutation
        }

        // Save the round keys
        for (int i = 0; i < 16; i++) {
            this->roundKeys[i] = roundKeys[i];
        }
    }

    bitset<48> applyPC2(bitset<56> key) {
        bitset<48> roundKey;

        for (int i = 0; i < 48; i++) {
            roundKey[i] = key[PC2[i] - 1];
        }

        return roundKey;
    }

    void splitReductedKey() {
        for (int i = 0; i < 28; i++) {
            leftHalf[i] = reducedKey[i];
            rightHalf[i] = reducedKey[i + 28];
        }
    }

    bitset<56> keyPermutation() {
        bitset<56> keyReduced;

        for (int i = 0; i < 56; i++) {
            keyReduced[i] = keyAsBinary[PC1[i] - 1];
        }

        // cout << "Key reduced: ";
        // printAsBinary(keyReduced);

        return keyReduced;
    }

    static bool evenParity(const bitset<64> &keyAsBinary) {
        return keyAsBinary.count() % 2 == 0;
    }

    static void setLeastSignificantBit(bitset<8> &bitArray, int value) {
        bitArray[0] = value;
    }

    static bitset<64> toBinary(const string &key) {
        bitset<64> keyAsBinary;

        if (key.length() != 8)
            throw std::invalid_argument("Key must be 8 characters (64 bit) long");

        for (int i = 0; i < key.length(); i++) {
            char currentChar = key[i];
            bitset<8> characterAsBinary(currentChar);

            for (int j = 0; j < 8; j++) {
                bool currentBit = characterAsBinary[j];
                keyAsBinary[i * 8 + j] = currentBit;
            }
        }

        return keyAsBinary;
    }

    void generateKey(bitset<64> bitset) {
        if (evenParity(bitset)) {
            // cout << "Key has even parity" << endl;
            addParity(bitset); // The key should have odd parity
        } else {
            // cout << "Key has odd parity" << endl;
        }
    }

    void addParity(bitset<64> &keyAsBinary) {
        for (int i = 0; i < 8; i++) {
            bitset<8> block = (keyAsBinary >> (i * 8)).to_ullong();

            if (block.count() % 2 == 0) {
                // Set the least significant bit to 1
                block[0] = 1;

                // Put the modified block back into the key
                keyAsBinary &= ~(bitset<64>(255) << (i * 8)); // Clear the block
                keyAsBinary |= (block.to_ullong() << (i * 8)); // Set the modified block
            }
        }
    }

public:
    DES(string initial_key, string plaintext) : key(initial_key) {
        if (initial_key.length() != 8)
            throw std::invalid_argument("Key must be 8 characters (64 bit) long");

        if (plaintext.length() != 8)
            throw std::invalid_argument("Plaintext must be 8 characters (64 bit) long");

        // Key generation step ---------------------------------------------------------------------------------
        keyAsBinary = toBinary(initial_key);
        generateKey(keyAsBinary);

        reducedKey = keyPermutation(); // reduce the key to 56 bits - PC1

        // leftHalf and rightHalf are the left and right halves of the key
        splitReductedKey();

        // Rotation and Permutation - PC2
        rotateAndPermutate();

        // End of key generation step --------------------------------------------------------------------------

        // Plaintext generation step ---------------------------------------------------------------------------
        plaintextBits = toBinary(plaintext);

        // Initial permutation ---------------------------------------------------------------------------------
        plaintextBits = applyIPToPlaintext(plaintextBits);
        // End of initial permutation --------------------------------------------------------------------------
    }


    ~DES() {
    }

    bitset<64> encrypt() {
        // Encryption ------------------------------------------------------------------------------------------
        bitset<64> encryptedBits = startEncryptionRounds();
        // End of encryption -----------------------------------------------------------------------------------

        // Final permutation - IP^-1
        bitset<64> ciphertextBits;

        for (int i = 0; i < 64; i++) {
            ciphertextBits[i] = encryptedBits[IP[i] - 1];  // Reuse the IP array for the final permutation
        }

        return ciphertextBits;
    }

    static string bitsetToString(const bitset<64> &m_bitset) {
        string result;
        for (size_t i = 0; i < 64; i += 8) {
            bitset<8> byte;
            for (size_t j = 0; j < 8; j++) {
                byte[j] = m_bitset[i + j];
            }
            char asciiChar = static_cast<char>(byte.to_ulong());
            result += asciiChar;
        }
        return result;
    }

    template<size_t Size>
    void printAsBinary(const bitset<Size> &bitset) {
        for (size_t i = 0; i < Size; i++) {
            cout << bitset[i];
        }
        cout << endl;
    }

    string getKey() {
        return key;
    }

    bitset<64> getKeyAsBinary() {
        return keyAsBinary;
    }
};
