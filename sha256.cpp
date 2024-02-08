#include <iostream>
#include "SHA256Encoder.h"

int main()
{
	SHA256Encoder encoder;
    std::string message{ "hello world" };
    std::cout << encoder.encode(message) << std::endl;
}