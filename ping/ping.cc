#include "./ping.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

#include <iostream>

namespace passionFruit
{
    void pton(struct sockaddr_in &addr, char *argv, int &isDomain) {
        ::bzero(&addr, sizeof(struct sockaddr_in));
        if(::inet_pton(AF_INET, argv, &addr.sin_addr) == 1) {
            // the argv[1] is an IP address
            isDomain = 0;
        }
        /*
        else {
            // error, the argv[1] is maybe a domain name
            // isDomain = 1
        }
        */
    }

    /*----------------------------------------------------------------------------------*/
    /*----  struct hostent {                                                        ----*/
    /*----    char *h_name;         // offical name of host                         ----*/
    /*----    char **h_aliases;     // alias list                                   ----*/
    /*----    int h_addrtype;       // host address type                            ----*/
    /*----    int h_length;         // length of address                            ----*/
    /*----    char **h_addr_list;   // list of address                              ----*/
    /*----  };                                                                      ----*/
    /*----  #define h_addr h_addr_list[0]                                           ----*/
    /*----------------------------------------------------------------------------------*/

    void domaintoaddr(struct sockaddr_in &addr, char *argv) {
        // argv[1] may be a domain name
        ::bzero(&addr, sizeof(struct sockaddr_in));
        struct hostent *res;
        res = ::gethostbyname(argv);
        if(res == nullptr) {
            // error,
            // argv[1] is neither the domain nor the correct IP address string
            std::cout << "\tcant't pint the network address!" << std::endl;
            std::cout << "\tyour domain name(or IP address) may be wrong!" << std::endl;
            std::cout << "\tinput the correct domain name(or IP address) again!" << std::endl;
            exit(-1);
        }

        // h_addr_list[*] are network byte order
        ::strcpy((char*)&addr.sin_addr, res->h_addr_list[0]);
    }

    void getNumOfICMP(int &d, char *argv) {
        // covert a string to a integer
        d = ::atoi(argv);
        if(d <= 0) {
            std::cout << "please specify the value that send ICMP packets!" << std::endl;
            exit(-1);
        }
    }

    unsigned short checksum(unsigned short *icmp, int len) {
        // sum first then inverse code is the same thing
        // as taking inverse code first and then sum again
        unsigned int sum  = 0;
        unsigned short ret;
        while(len > 1) {
            sum += *icmp++;
            len -= 2;
        }
        if(len == 1) {
            sum += *(unsigned char*)icmp;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        ret = ~sum;
        return ret;
    }
}







