#pragma once
#include <array>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <bitset>

class SHA256Encoder
{
public:
	using BitsVector = std::vector<bool>;

private:
	static constexpr size_t HASH_LENGTH{ 8 };
	static constexpr size_t BLOCK_LENGTH{ 64 };
	static constexpr size_t CHUNK_LENGTH{ 512 };
	static const std::array<const uint32_t, BLOCK_LENGTH> k;
	std::array<uint32_t, HASH_LENGTH> hashValues;

public:
	SHA256Encoder();
	~SHA256Encoder();
	std::string encode(const std::string& message);

private:
	void initVariables();
	BitsVector getBitsFromMessage(const std::string& message);
	BitsVector getHash(const BitsVector& bits);
	std::string getMessageFromBits(const BitsVector& bits);

	BitsVector getPadded(const BitsVector& bits);
	void processChunk(const BitsVector& bitsChunk);

	std::string appendSingleBit(const std::string& message);
	size_t getK(const uint64_t l);

	static uint32_t rotateRight(const uint32_t x, const int n);
	static uint32_t rotateLeft(const uint32_t x, const int n);
	static uint32_t shiftRight(const uint32_t x, const int n);
	static uint32_t shiftLeft(const uint32_t x, const int n);
	static uint32_t ternaryXOR(const uint32_t a, const uint32_t b, const uint32_t c);
};

