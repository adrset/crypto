#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdio.h> //printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <netdb.h>	//hostent
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>

const std::string OUT_FOLDER = "out";
// Program stworzono korzystając z :
// https://stackoverflow.com/questions/17852325/how-to-convert-the-x509-structure-into-string
// https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/

// Kompilacja g++ getcert.cpp -o plik -L/usr/lib/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu -lssl -lcrypto -std=c++11
struct mapping {
    mapping(std::string h, std::string i) : hostname(h), ip(i){};
    std::string hostname;
    std::string ip;
};

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



std::string hostname_to_ip(std::string hostname) {
	struct hostent *he;
	struct in_addr **addr_list;
		
	if ( (he = gethostbyname( hostname.c_str() ) ) == nullptr) {
		throw "Could not get hostname";
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(unsigned int i = 0; addr_list[i] != nullptr; i++) 
	{   
		//Return the first one;
        std::string istr(inet_ntoa(*addr_list[i]));
		return istr;
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

std::vector<mapping> getIPMapping(std::string fname) {
    std::ifstream domainfile(fname);
    std::string tmp;
    std::vector<mapping> domains;
    while (domainfile >> tmp) {
        std::string ipstr;
        ipstr =hostname_to_ip(tmp.c_str());
        domains.push_back(mapping(tmp, ipstr));
    }
    domainfile.close();

    return domains;
}
 
int main(int argc, char **argv) {
	
	if (argc < 2) {
		throw "No input parameters!";
	}

    std::vector<mapping> domains = getIPMapping(argv[1]);
        
    for (auto& it: domains) {
        struct sockaddr_in sa;
        SSL*     ssl;
        X509*    server_cert;
    
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());
    
        int sd = ::socket (AF_INET, SOCK_STREAM, 0);
        if (sd!=-1 && ctx!=nullptr) {
        
           
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
                                FILE * pliczek = fopen((OUT_FOLDER + "/" + it.hostname + ".txt").c_str(), "w");
                                PEM_write_RSA_PUBKEY(pliczek, rsapubkey);
                                RSA_free(rsapubkey);
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
}
