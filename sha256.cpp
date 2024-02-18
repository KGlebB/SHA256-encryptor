#include <iostream>
#include "SHA256Encoder.h"
#include "dsa.h"

int main()
{
	SHA256Encoder encoder;
    std::string message{ "hello world" };
    std::cout << "Hash: " << encoder.encode(message) << std::endl;
	dsa d;
	auto [r, s] = d.sing(message);
	std::cout << (d.verify(message, r, s) ? "Verified" : "Not verified") << std::endl;
}