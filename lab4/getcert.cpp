#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <netdb.h>	//hostent
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
const std::string OUT_FOLDER = "out";
// Program stworzono korzystając z :
// https://stackoverflow.com/questions/17852325/how-to-convert-the-x509-structure-into-string
// https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/

// Kompilacja g++ getcert.cpp -o plik -L/usr/lib/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu -lssl -lcrypto -std=c++11
struct mapping {
    mapping(std::string h, std::string i) : hostname(h), ip(i){};
    std::string hostname;
    std::string ip;
    std::string pubkey;
    bool duplicate = false;
    void setPubkey(std::string in) {pubkey = in;}
    
};

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

std::ostream& operator<<(std::ostream& in, mapping m) {
        in << "h:" << m.hostname <<std::endl << "ip:" << m.ip <<std::endl  << "pkey:" << m.pubkey <<std::endl << std::endl ;
        return in;
    }

std::string cleanseKey(std::string in) {
    std::string s(in);
    std::string toReplace1("-----BEGIN PUBLIC KEY-----");
    std::string toReplace2("-----END PUBLIC KEY-----");
    size_t pos = s.find(toReplace1);
    s = s.replace(pos, toReplace1.length(), "");
    pos = s.find(toReplace2);
    s = s.replace(pos, toReplace2.length(), "");
    s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
    return s;

}

char *X509_to_PEM(X509 *cert) {

    BIO *bio = nullptr;
    char *pem = nullptr;

    if (nullptr == cert) {
        return nullptr;
    }

    bio = BIO_new(BIO_s_mem());
    if (nullptr == bio) {
        return nullptr;
    }

    if (0 == PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return nullptr;
    }

    pem = (char *) malloc(bio->num_write + 1);
    if (nullptr == pem) {
        BIO_free(bio);
        return nullptr;    
    }

    memset(pem, 0, bio->num_write + 1);
    BIO_read(bio, pem, bio->num_write);
    BIO_free(bio);
    return pem;
}
int a = 0;

std::string* hostname_to_ip2(std::string hostname) {
	struct hostent *he = gethostbyname( hostname.c_str());
	struct in_addr **addr_list;
		
	if(he ==  nullptr) {
        return nullptr;
    }

	addr_list = (struct in_addr **) he->h_addr_list;

	for(unsigned int i = 0; addr_list[i] != nullptr; i++) 
	{   
		//Return the first one;
        std::string istr(inet_ntoa(*addr_list[i]));
		return new std::string(istr);
	}
	
    throw "Reached end of hostname_to_ip !!! No not null address";

}

RSA* getPublicKey(X509* cert)
{
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    return rsa;
}

BIGNUM* getN(RSA* rsa) {
    return rsa->n;
}

std::vector<mapping> getIPMapping(char* fname) {
    std::ifstream domainfile(fname);
    std::string tmp;
    std::vector<mapping> domains;
    while (domainfile >> tmp) {
        std::string* ipstr = hostname_to_ip2(tmp);

        if(ipstr == nullptr) {
            continue;
        }
        std::cout << tmp.c_str() << " -> " << *ipstr << std::endl;

        domains.push_back(mapping(tmp, *ipstr));

    }
    domainfile.close();

    return domains;
}

std::vector<mapping> getDuplicates(std::vector<mapping> in) {
    std::vector<mapping> out;
    for (unsigned int ii=0; ii< in.size() -1; ii++ ){
        for (unsigned int jj=ii + 1; jj< in.size(); jj++ ){
            if (in[ii].pubkey.compare(in[jj].pubkey) == 0 && in[ii].pubkey.length() > 20) {
                if(!in[ii].duplicate){
                    out.push_back(in[ii]);
                    in[ii].duplicate = true;
                }
                if(!in[jj].duplicate){
                    out.push_back(in[jj]);
                    in[jj].duplicate = true;
                }

            }
        }
    }
    return out;
}

void freeBN(std::vector<BIGNUM*> vec){
    for(auto* it: vec) {
        BN_free(it);
    }
}

void listAll(std::vector<mapping> in) {
    for (mapping& it: in) {
        std::cout << it;
    }
}

void createDir(std::string name){
    struct stat st = {0};

    if (stat(name.c_str(), &st) == -1) {
        mkdir(name.c_str(), 0700);
        std::cout << "Creating directory '" << name << "'." << std::endl;
    }   
}

 
int main(int argc, char **argv) {
	struct timeval  timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
	if (argc < 2) {
		throw "No input parameters!";
	}
    std::cout << "Mapping start" << std::endl;
    std::vector<mapping> domains = getIPMapping(argv[1]);
    std::cout<< "Mapping done" << std::endl;
    createDir("out");
    std::vector <BIGNUM*> rsa_n;
    for (auto& it: domains) {
        struct sockaddr_in sa;
        SSL*     ssl;
        X509*    server_cert;
    
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());
    
        int sd = ::socket (AF_INET, SOCK_STREAM, 0);
        if (sd!=-1 && ctx!=nullptr) {
        
            setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

            memset (&sa, '\0', sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = inet_addr (it.ip.c_str());   /* Server IP */
            sa.sin_port        = htons     (443);           /* Server Port number */
            
            int err = ::connect(sd, (struct sockaddr*) &sa, sizeof(sa));
            if (err!=-1) {   
                ssl = SSL_new (ctx);
                if (ssl!=nullptr) {	
                    SSL_set_fd(ssl, sd);
                    err = SSL_connect(ssl);
                    if (err!=-1) {

                        server_cert = SSL_get_peer_certificate(ssl);
                        if (server_cert!=nullptr) {
                            std::cout << "Fetched certificate for " <<  it.hostname << std::endl;
                            
                            RSA *rsapubkey = getPublicKey(server_cert);
                            if (nullptr != rsapubkey) {
                                rsa_n.push_back(BN_dup(getN(rsapubkey)));
                                FILE * pliczek = fopen((OUT_FOLDER + "/" + it.hostname + ".txt").c_str(), "w");
                                PEM_write_RSA_PUBKEY(pliczek, rsapubkey);
                                RSA_free(rsapubkey);
                                fflush(pliczek);
                                fclose(pliczek);
                                std::ifstream t(OUT_FOLDER + "/" + it.hostname + ".txt");
                                std::string tmp;
                                getline( t, tmp, '\0');

                                t.close();
                                it.setPubkey(cleanseKey(tmp));
                            }
                            X509_free (server_cert);
                        }
                    }
                    SSL_free (ssl);
                }
                ::close(sd);
            }
            
        }
        SSL_CTX_free (ctx);
    }

    for (auto* it : rsa_n) {
        //printf("%s\n", BN_bn2dec(it));

    }

    // https://github.com/OneSignal/openssl/blob/master/crypto/bn/bn_gcd.c
    // MAX Stack pool is 16! BN_CTX (BIGNUMBER stack)
    unsigned int const MAX_CTX = 16;
    BIGNUM* tmp = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int ret = 0;
    for (unsigned int ii = 0; ii < rsa_n.size(); ii++){
        for (unsigned int jj = ii + 1; jj < rsa_n.size(); jj++){
            if (BN_cmp(rsa_n[ii], rsa_n[jj]) == 0) {
                std::cout << std::endl;
                printf("%s\n\nand \n\n%s \n\n are EQUAL\n\n", BN_bn2dec(rsa_n[ii]), BN_bn2dec(rsa_n[jj]));
                std::cout << "================================" <<std::endl;
            }else {
                ret = BN_gcd(tmp, rsa_n[ii], rsa_n[jj], ctx);
                std::cout << std::endl;
                printf("%s\n\nvs \n\n%s \n\n gcd is \n\n%s\n\n", BN_bn2dec(rsa_n[ii]), BN_bn2dec(rsa_n[jj]), BN_bn2dec(tmp));
                std::cout << "================================" <<std::endl;
            }
            

        }
    }

    BN_CTX_free(ctx);
    BN_free(tmp);
    freeBN(rsa_n);



}


