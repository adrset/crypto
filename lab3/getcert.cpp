#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509.h>
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

    BIO *bio = NULL;
    char *pem = NULL;

    if (NULL == cert) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return NULL;
    }

    pem = (char *) malloc(bio->num_write + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;    
    }

    memset(pem, 0, bio->num_write + 1);
    BIO_read(bio, pem, bio->num_write);
    BIO_free(bio);
    return pem;
}



int hostname_to_ip(const char * hostname , char* ip) {
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
		
	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{
		// get the host info
		herror("gethostbyname");
		return 1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
		strcpy(ip , inet_ntoa(*addr_list[i]) );
		return 0;
	}
	
	return 1;
}

std::vector<mapping>& getIPMapping(std::string fname) {
    std::ifstream domainfile(fname);
    std::string tmp;
    std::vector<mapping> domains;
    while (domainfile >> tmp) {
        char ip[100];
        hostname_to_ip(tmp.c_str(),ip);
        std::string iptr(ip);
        domains.push_back(mapping(tmp, ip));
    }
    domainfile.close();

    return domains;
}
 
int main(int argc, char **argv) {
	
	if (argc < 2) {
		fprintf(stderr, "NO INPUT ARGUMENTS");
		return -1;
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
        if (sd!=-1 && ctx!=NULL) {
        
           
            memset (&sa, '\0', sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = inet_addr (it.ip.c_str());   /* Server IP */
            sa.sin_port        = htons     (443);           /* Server Port number */

            int err = ::connect(sd, (struct sockaddr*) &sa, sizeof(sa));
            if (err!=-1)
            {   
                ssl = SSL_new (ctx);
                if (ssl!=NULL)
                {	
                    SSL_set_fd(ssl, sd);
                    err = SSL_connect(ssl);
                    if (err!=-1)
                    {

                        server_cert = SSL_get_peer_certificate(ssl);
                        if (server_cert!=NULL)
                        {
                            char * cert = X509_to_PEM(server_cert);
                            std::cout << "Fetched certificate for " <<  it.hostname << std::endl;
                            X509_free (server_cert);
                            std::ofstream output(OUT_FOLDER + "/" + it.hostname + ".txt");
                            output << (cert);
                            free (cert);
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
