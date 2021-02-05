#include "include.h"
#include "DNSSearch.h"

int main(int argc, char **argv) 
{
    // check the command line
    if(argc != 2) {
        std::cout << "command line fromat error!" << std::endl;
        exit(-1);
    }

    DNS Event;
    char *dns_server_ip = DNS_SERVER_IP;
    Event.start(argv[1]);
    return 0;
}