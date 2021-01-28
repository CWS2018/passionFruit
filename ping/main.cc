#include <iostream>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "./ping.h"

/*----------------------------------------------------------------------------------------*/
/*---- command line parameter format,such as:                                         ----*/
/*----      ping baidu.com(or 127.0.0.1)    --four ICMP packets are sent by default   ----*/
/*----      ping ×××××× num                --custmize sending (num) ICMP packets      ----*/
/*----------------------------------------------------------------------------------------*/

#define IP_SIZE 65535
#define ICMP_SIZE 64
#define ICMP_HEAD 8

int main(int argc, char **argv)
{
    // check the command line arguments
    if(argc != 2 && argc != 3) {
        std::cout << "command line arguments error!" << std::endl;
        exit(-1);
    }

    /*---------------------------------------------------------------------------------*/
    /*----  struct in_addr {                                                       ----*/
    /*----    in_addr_t addr;       // 32-bit IPv4 address                         ----*/
    /*----  };                                                                     ----*/
    /*----  struct sockaddr_in {                                                   ----*/
    /*----    sa_family_t sin_family;       // AF_INET                             ----*/
    /*----    in_port_t sin_port;           // 16-bit TCP or UDP port number       ----*/
    /*----    struct in_addr sin_addr;      // 32-bit IP address                   ----*/
    /*----    char sin_zero[8];             // nused                               ----*/
    /*----  };                                                                     ----*/
    /*---------------------------------------------------------------------------------*/

    // determine whether argv[1] is a domain name or an IP address
    // get sockaddr_in
    int isDomain = 1;
    struct sockaddr_in destAddr;
    passionFruit::pton(destAddr, argv[1], isDomain);
    if(isDomain) {
        // the argv[1] is a domain name
        // search real IP addr by DNS, call gethostbyname(...)
        passionFruit::domaintoaddr(destAddr, argv[1]);
    }
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 11111;
    
    // the number of ICMP packets
    int icmpPackets = 4;                                // by default
    if(argc == 3) {
        // user customizes ICMP packets, there's argv[2]
        passionFruit::getNumOfICMP(icmpPackets, argv[2]);
    }

    char sendbuf[ICMP_SIZE];
    char recebuf[IP_SIZE];
    int sendpackets = 0;                                    // number of packets sent
    int recepackets = 0;                                    // number of packets received
    struct ICMP *sendicmp, *receicmp;
    struct IPHeader *receip;
    sendicmp = (struct ICMP*)sendbuf;
    receip = (struct IPHeader*)recebuf;

    // initlize ICMP
    sendicmp->type = 8;
    sendicmp->code = 0;
    sendicmp->id = ::getpid();
    strcpy(sendicmp->data, "this is my baby ping!");

    // create raw socket
    int rsk = -1;
    rsk = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(rsk == -1) {
        std::cout << "create socket failed!" << std::endl;
        ::close(rsk);
        exit(-1);
    }

    std::cout << "ping " << argv[1] << "(" 
              << ::inet_ntoa(destAddr.sin_addr)
              << ") " << (ICMP_SIZE-8) <<  " bytes of data:"
              << std::endl;

    /*----------------------------------------------------------*/
    /*----  struct timaval {                                ----*/
    /*----    time_t tv_sec;        // seconds              ----*/
    /*----    suseconds_t tv_usec;  // microseconds         ----*/
    /*----  };                                              ----*/
    /*----------------------------------------------------------*/

    struct timeval start, end;      // caculate ttl

    while(sendpackets < icmpPackets) {
        //send icmpPackets echo requests
        //receive the echo replies
        sendicmp->seq = sendpackets+1;
        sendicmp->checksum = 0;
        sendicmp->checksum = passionFruit::checksum((unsigned short*)sendicmp, ICMP_SIZE);

        ::gettimeofday(&start, NULL);

        // send ICMP echo request to destAddr
        if((::sendto(rsk, sendicmp, ICMP_SIZE, 0, (sockaddr*)&destAddr, sizeof(destAddr))) < 0) {
            // error, fail to send
            continue;
        }            
        ++sendpackets;              // success to send, +1

        // receive ICMP echo reply from destAddr
    again:
        if((::recvfrom(rsk, receip, IP_SIZE, 0, NULL, NULL)) < 0) {
            // fail to eceive, again
            goto again;
        }
        // take ICMP packet from IP packet
        //receicmp = (struct ICMP*)((char*)receip+(20/*(receip->ver_hlen << 4) >> 4 * 4*/));
        receicmp = (struct ICMP*)((char*)receip+(receip->ver_hlen & 15)*4);
        if(receicmp->type !=0 || receicmp->id != ::getpid() || receicmp->code != 0) {
            // the packet you received was not the packet you wanted
            // again
            goto again;
        }

        // sucess to receive ICMP echo reply
        ++recepackets;
        ::gettimeofday(&end, NULL);
        float rtt = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec-start.tv_usec)/1000.0f;
        std::cout << ICMP_SIZE << " bytes from " << ::inet_ntoa(destAddr.sin_addr)
                  << "(" << ::inet_ntoa(destAddr.sin_addr) << "): "
                  << "icmp_seq=" << receicmp->seq << "  ttl=" << receip->ttl
                  << "  time=" << rtt << "ms" << std::endl; 
    }
    
    ::close(rsk);
    return 0;
}