#include <cstdlib>
#include <string>
#include <iostream>
#include <random>
#include <cmath>
#include <deque>
#include <stdexcept>
#include <algorithm>
#include <numeric>


using std::string;
using std::deque;


class RSA {
private:
    unsigned long long p, q, t, modulus, publicKey, privateKey;
    unsigned long long clientPublicKey, clientModulus;

public:
    RSA(unsigned long long clientPublicKey = 0, unsigned long long clientModulus = 0,
        unsigned long long keySize = 65536) {
        p = generatePrime(keySize);
        q = generatePrime(keySize);

        modulus = p * q;
        t = totient(modulus);

        publicKey = generateE(t);
        privateKey = generateD(publicKey, t);

        this->clientPublicKey = clientPublicKey;
        this->clientModulus = clientModulus;
    }

    ~RSA() {}

    unsigned long long getModulus() {
        return modulus;
    }

    unsigned long long getPublicKey() {
        return publicKey;
    }

    unsigned long long getPrivateKey() {
        return privateKey;
    }

    unsigned long long getClientPublicKey() {
        return clientPublicKey;
    }

    unsigned long long getClientModulus() {
        return clientModulus;
    }

    static bool isPrime(unsigned long long num) {
        for (unsigned long long i = 2; i <= std::sqrt(num); i++) {
            if (num % i == 0) {
                return false;
            }
        }
        return true;
    }

    unsigned long long randomULong(unsigned long long min, unsigned long long max) {
        // Ensure that max is greater than or equal to min
        if (max < min)
            std::swap(min, max);

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned long long> distribution(min, max);
        return distribution(gen);
    }

    unsigned long long generatePrime(unsigned long long maxNum) {
        while (true) {
            unsigned long long num = randomULong(maxNum / 2, maxNum);
            if (isPrime(num)) {
                return num;
            }
        }
    }

    unsigned long long totient(unsigned long long n) {
        unsigned long long result = n;
        unsigned long long i = 2;

        while (i * i <= n) {
            if (n % i == 0) {
                result -= result / i;

                while (n % i == 0) {
                    n /= i;
                }
            }
            i++;
        }

        if (n > 1) {
            result -= result / n;
        }
        return result;
    }

    unsigned long long generateE(unsigned long long t) {
        for (unsigned long long e = 2; e < t; e++) {
            if (std::gcd(e, t) == 1) {
                return e;
            }
        }
        throw std::runtime_error("Error: Could not generate e");
    }

    unsigned long long generateD(unsigned long long publicKey, unsigned long long t) {
        unsigned long long k = 1;

        while ((k * t + 1) % publicKey != 0) {
            k++;
        }

        return (k * t + 1) / publicKey;
    }

    void setModulus(unsigned long long modulus) {
        this->modulus = modulus;
    }

    void setPublicKey(unsigned long long publicKey) {
        this->publicKey = publicKey;
    }

    void setPrivateKey(unsigned long long privateKey) {
        this->privateKey = privateKey;
    }

    void setClientPublicKey(unsigned long long publicKey) {
        this->clientPublicKey = publicKey;
    }

    void setClientModulus(unsigned long long modulus) {
        this->clientModulus = modulus;
    }

    static unsigned long long
    modularPow(unsigned long long base, unsigned long long exponent, unsigned long long modulus) {
        unsigned long long result = 1;
        base = base % modulus;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = (result * base) % modulus;
            }
            exponent >>= 1;
            base = (base * base) % modulus;
        }
        return result;
    }

    deque<unsigned long long> encrypt(const std::string &message) {
        if (clientModulus == 0 || clientPublicKey == 0) {
            throw std::runtime_error("Error: Client's modulus or public key is not set");
        }

        deque<unsigned long long> encrypted;
        // To Ascii
        for (long int i = 0; i < message.length(); i++) {
            int ascii_val = message.at(i);

            unsigned long long encrypted_value = modularPow(ascii_val, clientPublicKey, clientModulus);
            encrypted.push_back(encrypted_value);
        }

        return encrypted;

    }

    string decrypt(const deque<unsigned long long> &encryptedMessage) {
        unsigned long long modulus = this->modulus;
        unsigned long long privateKey = this->privateKey;

        string decrypted = "";
        for (long int i = 0; i < encryptedMessage.size(); i++) {
            unsigned long long x = encryptedMessage[i];

            unsigned long long decryptedValue = modularPow(x, privateKey, modulus);
            decrypted += static_cast<char>(decryptedValue);
        }

        return decrypted;
    }
};