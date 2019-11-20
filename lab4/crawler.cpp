#include <iostream>
#include <curl/curl.h>
#include <regex> //jeśli mamy standard C++0x
#include <stdio.h>
#include <vector>
#include <set>
#include <fstream>
/**
 * Euclidean algorithm 
 * 
 */
int gcd(unsigned int a_in, unsigned int b_in) {

    unsigned int c = 0, a = a_in, b = b_in;
    while (b != 0) {
        c = a % b;
        a = b;
        b = c;
    }

    return a;
}
/**
 * https://en.wikipedia.org/wiki/Binary_GCD_algorithm
 * 
 */
unsigned int gcd_bin(unsigned int u, unsigned int v) {
    // simple cases (termination)
    if (u == v)
        return u;

    if (u == 0)
        return v;

    if (v == 0)
        return u;

    // look for factors of 2
    if (~u & 1) // u is even
        if (v & 1) // v is odd
            return gcd_bin(u >> 1, v);
        else // both u and v are even
            return gcd_bin(u >> 1, v >> 1) << 1;

    if (~v & 1) // u is odd, v is even
        return gcd_bin(u, v >> 1);

    // reduce larger argument
    if (u > v)
        return gcd_bin((u - v) >> 1, v);

    return gcd_bin((v - u) >> 1, u);
}

std::string getDomain(std::string it) {
    std::string toReplace1("https://");
    std::string toReplace2("http://");
    size_t pos = it.find(toReplace1);
    if(pos < it.length())
        it = it.replace(pos, toReplace1.length(), "");
    pos = it.find(toReplace2);
    if(pos < it.length())
        it = it.replace(pos, toReplace2.length(), "");
    size_t found1 =it.find_first_of("/");
    it = it.substr(0, found1);
    return it;
}

std::set<std::string> getDomains(std::vector<std::string> in) {
        std::set<std::string> urls;
        for(auto& it : in) {
            std::string domain = getDomain(it);
            urls.insert(domain);
        }

        return urls;

}

size_t CurlWrite_CallbackFunc_StdString(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size*nmemb;
    try
    {
        s->append((char*)contents, newLength);
    }
    catch(std::bad_alloc &e)
    {
        //handle memory problem
        return 0;
    }
    return newLength;
}

int main(int argc, char** argv) {

    for (unsigned int ii = 10000; ii < 200000000; ii++) {
        unsigned int verdict = gcd(ii, (ii+1)^2);
        if (verdict != 1 && verdict != 3) 
            std::cout << verdict << std::endl;
    }

    if (argc < 2) {
        std::cout << "Please supply the url!"<<std::endl; 
        return 1;
    }

    std::string urlin(argv[1]);
    std::ofstream file("urls.txt");
    std::vector<std::string> urls;
    CURL *curl;
    CURLcode res;
    std::string subject;
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &subject);
        std::cout << urlin;
        curl_easy_setopt(curl, CURLOPT_URL, urlin);
        res = curl_easy_perform(curl);
        std::cout << res;
        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    //std::cout<<subject;
    try {
        std::regex pattern("<a\\s+(?:[^>]*?\\s+)?href=([\"'])(.*?)\\1");
        std::sregex_iterator next(subject.begin(), subject.end(), pattern);
        std::sregex_iterator end;
        while (next != end) {
            std::smatch match = *next;
            //std::cout << match.str() << "\n\n\n\n";
            std::string tmp = match.str();
            std::size_t found = tmp.find("href");
            tmp = tmp.substr(found + 6, tmp.length() - 1);
            found = tmp.find("\"");
            tmp = tmp.substr(0, found);
            if (tmp.substr(0,2).compare("//") == 0) {
                tmp = "http:" + tmp;
            } else if (tmp.substr(0,1).compare("/") == 0) {
                tmp = "http://" + getDomain(urlin) + tmp;
            }
            std::cout<<getDomain(urlin);
            urls.push_back(tmp);
            next++;
        } 
    } catch (std::regex_error& e) {
    
    }

    std::set<std::string> domains = getDomains(urls);
    for (auto& it : domains) {
        
        file << it << std::endl;
    }
    file.close();
}