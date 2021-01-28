#ifndef _PING_H_
#define _PING_H_

#include <netinet/in.h>

struct ICMP
{
    // ICMP request reply packet format
    uint8_t type;           // 8-bit
    uint8_t code;           // 8-bit
    uint16_t checksum;      // 16-bit
    uint16_t id;            // 16-bit, identify
    uint16_t seq;           // 16-bit sequence
    char data[0];           // used for dynamic allocation
};

struct IPHeader 
{
    // ip packet header format
    uint8_t ver_hlen;               // 4-bit versions + 4-bit header length
    uint8_t tos;                    // 8-bit TOS
    uint16_t tlen;                  // total length of IP packet
    uint16_t iden;                  // 
    uint16_t flag_offset;           // 3-bit flag + 13-bit slice offset
    uint8_t ttl;
    uint8_t protocal;
    uint16_t checksum;              // 16-bit header check sum
    uint32_t sa;                    // 32-bit source address
    uint32_t da;                    // 32-bit destination address
};

namespace passionFruit
{
    // if there's argv[2], get it for ICMP packets
    void getNumOfICMP(int &d, char *argv);

    // package gethostbyname(...), turn domain name to IP address
    void domaintoaddr(struct sockaddr_in &addr, char *argv);

    // and determine if argv[1] is a domain name
    // if not, isDomain = 0, and get sockaddr_in
    void pton(struct sockaddr_in &addr, char *argv, int &isDomain);

    // check sum
    unsigned short checksum(unsigned short *icmp, int size);
}

#endif