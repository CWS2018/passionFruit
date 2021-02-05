#ifndef DNSSEARCH_H_
#define DNSSEARCH_H_

#include "include.h"

#define DNS_PORT 53                                 //  DNS port
#define DNS_SERVER_IP "223.5.5.5"             //  DNS system IP address

#define MAX_SEND_COUNTS 3                           //  maximun number of message sent

// DNS flag field
// QR
#define DNS_FLAG_QR_QUERY 0                              // query
#define DNS_FLAG_QR_RESPONSE 1                           // DNS response

// opcode
#define DNS_FLAG_OPCODE_STANDARD_QUERY 0                 // standard query
#define DNS_FLAG_OPCODE_REVERSE_QUERY 1                  // reverse query
#define DNS_FLAG_OPCODE_STATUS 2                         // DNS server status

// rcode
#define DNS_FLAG_RCODE_NOERROR 0                         // no error
#define DNS_FLAG_RCODE_MESSAGEERROR 1                    // message error, the server can't understand the requested messahe
#define DNS_FLAG_RCODE_SERVERERROR 2                     // server error, the request could not be processed due to the server issues
#define DNS_FLAG_RCODE_NAMEERRO 3                        // name error, the domain name does not exit
//#define DNS_FLAG_RCODE 4-5

// query type
#define DNS_QUERY_TYPE_A 1                               // query IPv4 address
#define DNS_QUERY_TYPE_NS 2                              // query domain server
#define DNS_QUERY_TYPE_CNAME 5                           // query specification name
#define DNS_QUERY_TYPE_PTR 12                            // converse IP address into domain
#define DNS_QUERY_TYPE_HINFO 13                          // host info
#define DNS_QUERY_TYPE_MX 15                             // email exchange record
//#define DNS_QUERY_TYPE_AAAA 28                           // query IPv6 address   

// query class
#define DNS_QUERY_CALSS_IN 1                             // internet
//#define DNS_QUERY_CLASS_ANY 255                          // all class 

// DNS base header flag
typedef struct _DNS_HEADER_FLAG
{
    #if BIG_ENDIAN
    uint16_t rcode : 4;                                   // 
    uint16_t zero : 3;                                    // must be 0
    uint16_t RA : 1;                                      // support recursion(1)
    uint16_t RD : 1;                                      // recursion desired
    uint16_t TC : 1;                                      // truncated
    uint16_t AA : 1;
    uint16_t opcode : 4;
    uint16_t QR : 1;
    #else 
    uint16_t QR : 1;
    uint16_t opcode : 4;
    uint16_t AA : 1;
    uint16_t TC : 1;
    uint16_t RD : 1;
    uint16_t RA : 1;
    uint16_t zero : 3;
    uint16_t rcode : 4;
    #endif
} DNS_HEADER_FLAG, *DNS_HEADER_FLAG_PTR;

// DNS base header
typedef struct _DNS_HEADER
{
    uint16_t id;                                         // transfer id
    DNS_HEADER_FLAG flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t aditional_rrs;
    char other_data[0];                                  // for dynamic malloc
} DNS_HEADER, *DNS_HEADER_PTR;

#define DNS_HEADER_SIZE sizeof(DNS_HEADER)

// query question
typedef struct _DNS_QUERY_QUESTION
{
    uint16_t query_type;
    uint16_t query_class;
} DNS_QUERY_QUESTION, *DNS_QUERY_QUESTION_PTR;
#define DNS_QUERY_QUESTION_SIZE sizeof(DNS_QUERY_QUESTION)

// RRS 
typedef struct _DNS_RRS
{
    uint16_t query_type;
    uint16_t query_class;
    uint32_t ttl;
    uint16_t len;
    char other_data[0];
} DNS_RRS, *DNS_RRS_PTR;
#define DNS_RRS_SIZE sizeof(DNS_RRS)

class DNS
{
public:
    DNS();
    ~DNS();
    void start(char *domainname);
private:
    bool udp_start(char *domainname);
    void tcp_start(char *domainname);
    int construct_dns_message(char *domainname);
    void get_correct_domainname(char *domainname);
    void split(char *domainname);
    bool udp_send(int sendsize);
    bool udp_recv(int &recvsize);
    bool parsedata();
    int decodename(int &readsize, std::string &namestr);
    int decodename1(int &readsize, std::string &namestr);

    int _socket;
    struct sockaddr_in _to;
    std::vector<std::string> _labels;
    struct timeval _timeout;
    DNS_HEADER_PTR _DNS_HEADER_PTR_SEND;                        // the first address of query message
    DNS_HEADER_PTR _DNS_HEADER_PTR_RECV;                        // the first address of reply message
};

#endif