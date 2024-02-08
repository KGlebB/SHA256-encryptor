#include <iostream>
#include "SHA256Encoder.h"

int main()
{
	SHA256Encoder encoder;
    std::setlocale(LC_ALL, "C");
    std::cout << encoder.encode("hello world") << std::endl;
}