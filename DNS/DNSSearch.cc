#include "DNSSearch.h"
#include "include.h"

DNS::DNS() {
}
DNS::~DNS() {
    if(_socket != -1)
        close(_socket);
    free(_DNS_HEADER_PTR_SEND);
}

void DNS::start(char *domainname) {
    bool result = true;
    // first, send DNS message by UDP
    // if the reply message is up to 512 bytes, use TCP
    result = this->udp_start(domainname);
    if(!result) {
        this->tcp_start(domainname);
    }
}

bool DNS::udp_start(char *domainname) {
    bool result = false;
    int count = 0;

    // create socket and make sockaddr_in 
    _socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(_socket < 0) {
        std::cout << "can't create a socket" << std::endl;
    }
    _to.sin_family = AF_INET;
    _to.sin_port = htons(DNS_PORT);
    inet_aton(DNS_SERVER_IP, &_to.sin_addr);

    // construct a DNS message
    this->construct_dns_message(domainname);
    if(_DNS_HEADER_PTR_SEND == nullptr) {
        std::cout << "can't construct a DNS query message!" << std::endl;
        exit(-1);
    }

    // send DNS query message <= MAX_SEND_COUNTS times
    while(count < MAX_SEND_COUNTS) {
        count += this->udp_send();
    }
    return result;
}
void DNS::tcp_start(char *domainname) {
    //
}

int DNS::udp_send() {
    
}

void DNS::construct_dns_message(char *domainname) {
    //
    uint16_t dns_query_type = DNS_QUERY_TYPE_A;
    if(inet_aton(domainname, nullptr) != 0) {
        // domainname is an IP addr
        dns_query_type = DNS_QUERY_TYPE_PTR;
        //this->get_correct_domainname(domainname);
    }

    // pmalloc
    int message_size = DNS_HEADER_SIZE + strlen(domainname) + 2 + DNS_QUERY_QUESTION_SIZE;
    _DNS_HEADER_PTR_SEND = (DNS_HEADER_PTR)malloc(message_size);
    if(_DNS_HEADER_PTR_SEND == nullptr) {
        std::cout << "pmalloc for DNS requested message failed!" << std::endl;
        exit(-1);
    }
    bzero(_DNS_HEADER_PTR_SEND, message_size);

    // set base header
    _DNS_HEADER_PTR_SEND->id = getpid();

    _DNS_HEADER_PTR_SEND->flags.QR = DNS_FLAG_QR_QUERY;
    _DNS_HEADER_PTR_SEND->flags.opcode = DNS_FLAG_OPCODE_STANDARD_QUERY;
    _DNS_HEADER_PTR_SEND->flags.AA = 0;
    _DNS_HEADER_PTR_SEND->flags.TC = 0;
    _DNS_HEADER_PTR_SEND->flags.RD = 1;
    _DNS_HEADER_PTR_SEND->flags.RA = 0;
    _DNS_HEADER_PTR_SEND->flags.zero = 0;
    _DNS_HEADER_PTR_SEND->flags.rcode = 0;

    *(uint16_t*)&_DNS_HEADER_PTR_SEND->flags = htons(*(uint16_t*)&_DNS_HEADER_PTR_SEND->flags);

    _DNS_HEADER_PTR_SEND->questions = htons(1);
    _DNS_HEADER_PTR_SEND->answer_rrs = 0;
    _DNS_HEADER_PTR_SEND->authority_rrs = 0;
    _DNS_HEADER_PTR_SEND->aditional_rrs = 0;

    // set query name
    int pos = 0;
    this->split(domainname);
    for(auto label : _labels) {
        _DNS_HEADER_PTR_SEND->other_data[pos++] = (char)label.length();
        memcpy(&_DNS_HEADER_PTR_SEND->other_data[pos], label.c_str(), label.length());
        pos += label.length();
    }
    _DNS_HEADER_PTR_SEND->other_data[pos] = 0;

    DNS_QUERY_QUESTION_PTR DQQP = (DNS_QUERY_QUESTION_PTR)&_DNS_HEADER_PTR_SEND->other_data[pos+1];
    DQQP->query_type = htons(dns_query_type);
    DQQP->query_class = htons(DNS_QUERY_CALSS_IN);

}

void DNS::get_correct_domainname(char *domainname) {
    //  waiting
}

void DNS::split(char *domainname) {
    std::string temp = domainname;
    int s_pos = 0, e_pos;
    while((e_pos = temp.find('.', s_pos)) != std::string::npos) {
        _labels.push_back(temp.substr(s_pos, e_pos - s_pos));
        s_pos = e_pos + 1;
    }
    _labels.push_back(temp.substr(s_pos, temp.length() - s_pos));
}



