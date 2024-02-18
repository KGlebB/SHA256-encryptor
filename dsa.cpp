#include "dsa.h"

std::pair<int, int> dsa::sing(const std::string& message)
{
    initRandom();
	const auto h{ getH(message) };
	auto k{ getK() };
	auto r{ getR(k) };
	auto s{ getS(r, k, h) };
	while (s == 0 || r == 0)
	{
		std::cout << "[DSA]" << std::endl;
		k = getK();
		r = getR(k);
		s = getS(r, k, h);
	}
    return std::make_pair(r, s);
}

bool dsa::verify(const std::string& message, const int r, const int s)
{
	const auto h{ getH(message) };
	auto w{ modInverse(s, Q) };
	std::cout << "[DSA] W = " << w << std::endl;
	auto u1{ positiveModulo(h * w, Q) };
	std::cout << "[DSA] U1 = " << u1 << std::endl;
	auto u2{ positiveModulo(r * w, Q) };
	std::cout << "[DSA] U2 = " << u2 << std::endl;
	auto v{ (((int)pow(G, u1) % P) * ((int)pow(Y, u2) % P)) % P % Q };
	std::cout << "[DSA] V = " << v << std::endl;
	return v == r;
}

void dsa::initRandom()
{
    srand(static_cast<unsigned>(time(nullptr)));
}

int dsa::getK()
{
	const auto k{ rand() % Q };
	std::cout << "[DSA] K = " << k << std::endl;
    return k;
}

int dsa::getR(int k)
{
	const auto r{ ((int)(pow(G, k)) % P) % Q };
	std::cout << "[DSA] R = " << r << std::endl;
    return r;
}

int dsa::getS(int r, int k, int h)
{
	const auto s{ positiveModulo((modInverse(k, Q) * (h + X * r)), Q) };
	std::cout << "[DSA] S = " << s << std::endl;
	return s;
}

int dsa::getH(const std::string& message)
{
	SHA256Encoder encoder;
	std::bitset<32> bits{ encoder.encodeToBits(message).to_string().substr(224) };
	auto h{ (int)(bits.to_ulong() >> 8) };
	std::cout << "[DSA] H = " << h << std::endl;
	return h;
}


std::tuple<int, int, int> dsa::extendedGCD(int a, int b)
{
	if (a == 0)
	{
		return std::make_tuple(b, 0, 1);
	}
	auto [gcd, x1, y1] = extendedGCD(b % a, a);
	auto x{ y1 - (b / a) * x1 };
	auto y{ x1 };
	return std::make_tuple(gcd, x, y);
}

int dsa::modInverse(int a, int b)
{
	auto [x, y, z] = extendedGCD(a, b);
	return y;
}

int dsa::positiveModulo(int a, int b)
{
	return (a % b + b) % b;
}
