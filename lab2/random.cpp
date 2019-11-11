#include <random>
#include <fstream>
#include <iostream>

int main() {
	std::ofstream plik("goodgen.bin", std::ios::binary);
	std::random_device device;
	std::mt19937 generator(device());
	std::uniform_int_distribution<unsigned long long int> distribution(1,1.8446744e+19);
 
	for (size_t i = 0; i < 10000000; ++i) {
		unsigned long long int tmp = distribution(generator);
		plik.write((char*)&tmp, sizeof(unsigned long long int));
	}
	plik.close();

	return 0;
}
