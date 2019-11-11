#include <iostream>
#include <fstream>
class lcg{
	private: 
		unsigned long long int g,c,m,f;
	public:
		lcg(){};
		lcg(unsigned long long int i_g, unsigned long long int i_c,unsigned long long int i_m,unsigned long long int i_f) :g(i_g), c(i_c), m(i_m), f(i_f) {}
		unsigned long long int iteration(){this->f=(this->g*this->f+this->c)%m;return this->f;}
		unsigned long long int getf(){return this->f;}
		double getm(){return ((this->m)-1.0);}
};

int main(int argc, char** argv){
	//czesc pierwsza
	std::ofstream plik("liczby.bin", std::ios::binary);
	lcg lcg1(134775813,1,1.8446744e+19,1);

	for(unsigned int ii=0;ii<100000000;ii++){
		unsigned long long int val = lcg1.iteration();
		plik.write((char*)&val, sizeof(unsigned long long int));		
	}
}
