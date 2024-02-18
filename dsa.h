#pragma once
#include <string>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <iostream>
#include "SHA256Encoder.h"

class dsa
{
private:
	static const int Q{ 5 };
	static const int P{ 11 };
	static const int G{ 4 };
	static const int X{ 2 };
	static const int Y{ 16 };

public:
	dsa() = default;
	~dsa() = default;
	std::pair<int, int> sing(const std::string& message);
	bool verify(const std::string& message, int r, int s);

private:
	void initRandom();
	int getK();
	int getR(int k);
	int getS(int r, int k, int h);
	int getH(const std::string& message);

	std::tuple<int, int, int> extendedGCD(int a, int b);
	int modInverse(int a, int b);

	int positiveModulo(int a, int b);
};

