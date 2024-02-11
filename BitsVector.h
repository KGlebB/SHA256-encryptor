#pragma once
#include <vector>
#include <algorithm>

class BitsBlock
{
private:
	uint32_t bits;
public:
	BitsBlock() = default;
	BitsBlock(const uint32_t bits);

	static BitsBlock fromBits(const std::vector<bool>& bits);
private:
};

