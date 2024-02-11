#include "BitsVector.h"

BitsBlock::BitsBlock(const uint32_t bits)
	: bits{ bits }
{
}

BitsBlock BitsBlock::fromBits(const std::vector<bool>& bits)
{
	size_t n{ std::max(bits.size(), 32ull) };
	uint32_t result{ 0 };
	for (size_t i{ 0 }; i < n; ++i)
	{
		result <<= 1;
		if (bits[i]) result |= 1;
	}
	return BitsBlock();
}
