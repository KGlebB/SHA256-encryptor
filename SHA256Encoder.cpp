#include "SHA256Encoder.h"

/* First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311 */
const std::array<const uint32_t, 64>SHA256Encoder::k {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

SHA256Encoder::SHA256Encoder()
{
	initVariables();
}

SHA256Encoder::~SHA256Encoder()
{

}

std::string SHA256Encoder::encode(const std::string& message)
{
    initVariables();
	const auto bits{ getBitsFromMessage(message) };
    const auto hash{ getHash(bits) };
	const auto result{ getMessageFromBits(hash) };
    return result;
}

SHA256Encoder::BitsVector SHA256Encoder::getBitsFromMessage(const std::string& message)
{
    BitsVector bits;

    for (char c : message) 
    {
        for (int i{ 7 }; i >= 0; --i)
        {
            bits.push_back((c >> i) & 1);
        }
    }

    return bits;
}

std::string SHA256Encoder::getMessageFromBits(const BitsVector& bits)
{
    std::stringstream hexString;
    hexString << std::hex << std::setfill('0');
    for (size_t i = 0; i < bits.size(); i += 4)
    {
        char hexChar = 0;
        for (size_t j{ 0 }; j < 4; ++j)
        {
            hexChar = (hexChar << 1) | static_cast<char>(bits[i + j]);
        }
        hexString << std::setw(1) << static_cast<int>(static_cast<unsigned char>(hexChar));
    }
    return hexString.str();
}

SHA256Encoder::BitsVector SHA256Encoder::getHash(const BitsVector& bits) {
    const auto paddedBits{ getPadded(bits) };

    for (size_t i{ 0 }; i < paddedBits.size(); i += CHUNK_LENGTH) {
        BitsVector chunk(paddedBits.begin() + i, paddedBits.begin() + i + CHUNK_LENGTH);
        processChunk(chunk);
    }

    BitsVector hashBits;
    for (uint32_t hashValue : hashValues) {
        for (int i = 31; i >= 0; --i) {
            hashBits.push_back((hashValue >> i) & 1);
        }
    }
    return hashBits;
}

/* Preprocess. Make message to look like: 
   <original message of length L> 1 <K zeros> <L as 64 bit integer>,
   (the number of bits will be a multiple of 512) */
SHA256Encoder::BitsVector SHA256Encoder::getPadded(const BitsVector& bits)
{
    uint64_t originalLength{ bits.size() };
    auto paddedBits{ bits };
    paddedBits.push_back(1);
    size_t k{ getK(originalLength) };
    for (size_t i{ 0 }; i < k; ++i)
    {
        paddedBits.push_back(0);
    }
    for (int i{ 63 }; i >= 0; --i) {
        paddedBits.push_back((originalLength >> i) & 1);
    }
    return paddedBits;
}

void SHA256Encoder::processChunk(const BitsVector& bitsChunk)
{
    std::array<uint32_t, 64> words{};

    // copy bits chunk into first 16 words
    for (size_t i{ 0 }; i < 16; ++i) {
        words[i] = 0;
        for (int j = 0; j < 32; ++j) {
            words[i] |= static_cast<uint32_t>(bitsChunk[i * 32 + j]) << (31 - j);
        }
    }

	// extend the first 16 words to remaining 48 words
    for (size_t i{ 16 }; i < 64; ++i) {
        uint32_t s0{ rotateRight(words[i - 15], 7) ^ rotateRight(words[i - 15], 18) ^ shiftRight(words[i - 15], 3) };
        uint32_t s1{ rotateRight(words[i - 2], 17) ^ rotateRight(words[i - 2], 19) ^ shiftRight(words[i - 2], 10) };
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    uint32_t a{ hashValues[0] };
    uint32_t b{ hashValues[1] };
    uint32_t c{ hashValues[2] };
    uint32_t d{ hashValues[3] };
    uint32_t e{ hashValues[4] };
    uint32_t f{ hashValues[5] };
    uint32_t g{ hashValues[6] };
    uint32_t h{ hashValues[7] };

	// compress the 64 words into hash values
    for (size_t i{ 0 }; i < 64; ++i) {
        uint32_t S1{ rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25) };
        uint32_t ch{ (e & f) ^ ((~e) & g) };
        uint32_t temp1{ h + S1 + ch + k[i] + words[i] };
        uint32_t S0{ rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22) };
        uint32_t maj{ (a & b) ^ (a & c) ^ (b & c) };
        uint32_t temp2{ S0 + maj };

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hashValues[0] += a;
    hashValues[1] += b;
    hashValues[2] += c;
    hashValues[3] += d;
    hashValues[4] += e;
    hashValues[5] += f;
    hashValues[6] += g;
    hashValues[7] += h;
}

std::string SHA256Encoder::appendSingleBit(const std::string& message)
{
    return message + '\x80';
}

size_t SHA256Encoder::getK(const uint64_t l)
{
    size_t k = 0;
    while ((l + 1 + k + 64) % 512 != 0) ++k;
    return k;
}

uint32_t SHA256Encoder::rotateRight(const uint32_t x, const int n)
{
	return (x >> n) | (x << (32 - n));
}

uint32_t SHA256Encoder::rotateLeft(const uint32_t x, const int n)
{
	return (x << n) | (x >> (32 - n));
}

uint32_t SHA256Encoder::shiftRight(const uint32_t x, const int n)
{
	return x >> n;
}

uint32_t SHA256Encoder::shiftLeft(const uint32_t x, const int n)
{
    return x << n;
}

uint32_t SHA256Encoder::ternaryXOR(const uint32_t a, const uint32_t b, const uint32_t c)
{
    return (a ^ b) ^ c;
}


/* First 32 bits of the fractional parts of the square roots of the first 8 primes 2..19 */
void SHA256Encoder::initVariables()
{
	hashValues = std::array<uint32_t, HASH_LENGTH>{
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
}