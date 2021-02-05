#include "DNSSearch.h"
#include "include.h"

DNS::DNS() {
    _socket = -1;
    _DNS_HEADER_PTR_RECV = nullptr;
    _DNS_HEADER_PTR_SEND = nullptr;
    _timeout.tv_sec = 5;
    _timeout.tv_usec = 0;
}
DNS::~DNS() {
    if(_socket != -1)
        close(_socket);
    free(_DNS_HEADER_PTR_SEND);
    free(_DNS_HEADER_PTR_RECV);
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
    int sendsize = 0;

    // create socket and make sockaddr_in 
    this->_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(this->_socket < 0) {
        std::cout << "can't create a socket" << std::endl;
    }
    this->_to.sin_family = AF_INET;
    this->_to.sin_port = htons(DNS_PORT);
    inet_aton(DNS_SERVER_IP, &this->_to.sin_addr);

    // construct a DNS message
    sendsize = this->construct_dns_message(domainname);
    if(this->_DNS_HEADER_PTR_SEND == nullptr) {
        std::cout << "can't construct a DNS query message!" << std::endl;
        exit(-1);
    }

    // send DNS query message <= MAX_SEND_COUNTS times
    // receive the reply message
    while(!result) {
        if(!this->udp_send(sendsize)) {
            break;
        }

        // receive the reply message
        int recvsize = 512;

        // pmalloc 
        this->_DNS_HEADER_PTR_RECV = (DNS_HEADER_PTR)malloc(recvsize);
        if(this->_DNS_HEADER_PTR_RECV == nullptr) {
            std::cout << "cant't malloc memory to receive reply message(UDP)" << std::endl;
            std::cout << "change TO TCP" << std::endl;
            break;
        }
        bzero(this->_DNS_HEADER_PTR_RECV, recvsize);

        if(!this->udp_recv(recvsize)) {
            break;
        }
        if(recvsize < DNS_HEADER_SIZE) {
            std::cout << "recvsize < DNS_HEADER_SIZE\n";
            std::cout << "change to TCP" << std::endl;
            break;
        }

        // parse receive data
        if(!this->parsedata()) {
            break;
        }
        result = true;
    }
    return result;
}
void DNS::tcp_start(char *domainname) {
    //
}

bool DNS::parsedata() {
    int readsize = 0;

    if(this->_DNS_HEADER_PTR_RECV == nullptr) {
        std::cout << "the _DNS_HEADER_PTR_RECV is nullptr\nchange to TCP" << std::endl;
        return false;
    }

    *(uint16_t*)&this->_DNS_HEADER_PTR_RECV->flags = ntohs(*(uint16_t*)&this->_DNS_HEADER_PTR_RECV->flags);
    this->_DNS_HEADER_PTR_RECV->questions = ntohs(this->_DNS_HEADER_PTR_RECV->questions);
    this->_DNS_HEADER_PTR_RECV->answer_rrs = ntohs(this->_DNS_HEADER_PTR_RECV->answer_rrs);
    this->_DNS_HEADER_PTR_RECV->authority_rrs = ntohs(this->_DNS_HEADER_PTR_RECV->authority_rrs);
    this->_DNS_HEADER_PTR_RECV->aditional_rrs = ntohs(this->_DNS_HEADER_PTR_RECV->aditional_rrs);

    // check the header
    if(this->_DNS_HEADER_PTR_RECV->id != getpid() ||
       this->_DNS_HEADER_PTR_RECV->flags.QR != DNS_FLAG_QR_RESPONSE ||
       this->_DNS_HEADER_PTR_RECV->flags.rcode != DNS_FLAG_RCODE_NOERROR)
    {
        return false;
    }

    for(int i = 0; i < this->_DNS_HEADER_PTR_RECV->questions; ++i) {
        std::string namestr;
        readsize += this->decodename(readsize, namestr);
        DNS_QUERY_QUESTION_PTR P = (DNS_QUERY_QUESTION_PTR)&this->_DNS_HEADER_PTR_RECV->other_data[readsize];
        readsize += DNS_QUERY_QUESTION_SIZE;
    }

    // parse answer_rrs
    for(int i = 0; i < this->_DNS_HEADER_PTR_RECV->answer_rrs; ++i) {
        std::string namestr;
        readsize += this->decodename(readsize, namestr);

        DNS_RRS_PTR rrs_ptr = (DNS_RRS_PTR)&this->_DNS_HEADER_PTR_RECV->other_data[readsize];

        rrs_ptr->query_type = ntohs(rrs_ptr->query_type);
        rrs_ptr->query_class = ntohs(rrs_ptr->query_class);
        rrs_ptr->ttl = ntohs(rrs_ptr->ttl);
        rrs_ptr->len = ntohs(rrs_ptr->len);

        uint32_t ip = *(uint32_t*)rrs_ptr->other_data;
        struct sockaddr_in addr;
        memcpy(&addr.sin_addr.s_addr, &ip, sizeof(ip));
        std::cout << "ip:" << inet_ntoa(addr.sin_addr) << "\n";
        readsize += sizeof(ip);
    }
    return true;
}

int DNS::decodename(int readsize, std::string &namestr) {
    int offset = 0;
    int len = -1;
    bool isofff = false;

    while((len = this->_DNS_HEADER_PTR_RECV->other_data[readsize+offset]) != 0) {
        if((len & 0xC0) == 0xC0) {
            uint16_t jmp_pos = ntohs(*(uint16_t *)&this->_DNS_HEADER_PTR_RECV->other_data[readsize+offset]) & 0x3FFF;
            readsize = jmp_pos - DNS_HEADER_SIZE;
            this->decodename(readsize, namestr);
            isofff = true;
            offset += 2;
            break;
        }

        if(!namestr.empty()) {
            namestr += '.';
        }
        namestr.append((char*)&this->_DNS_HEADER_PTR_RECV->other_data[readsize+offset+1], len);
        offset += len + 1;
    }
    if(offset > 0 && !isofff) {
        offset += 1;
    }
    return offset;
}

bool DNS::udp_send(int sendsize) {
    int err = -1;
    err = sendto(_socket, (const char*)this->_DNS_HEADER_PTR_SEND, sendsize, 0, (struct sockaddr*)&this->_to, sizeof(this->_to));
    if(err == -1 || err != sendsize) {
        std::cout << "cant't send a UDP message!" << std::endl;
        std::cout << "change to TCP" << std::endl;
        return false;
    }
    return true;
}

bool DNS::udp_recv(int &recvsize) {
    int ready = 0;
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(this->_socket, &rfds);

    ready = select(this->_socket+1, &rfds, NULL, NULL, &this->_timeout);

    if(ready > 0) {
        int fromlen = 0;
        int retsize = 0;
        retsize = recvfrom(this->_socket, (char*)this->_DNS_HEADER_PTR_RECV, recvsize, 0, (struct sockaddr*)&this->_to, (socklen_t*)&fromlen);
        if(retsize < 0) {
            //std::cout << retsize << "\n" << this->_socket;
            std::cout << "can't recv reply message(UDP1)" << "\n" << "change to TCP" << std::endl;
            return false;
        }
        //std::cout << retsize;
        recvsize = retsize;
    } 
    else if(ready == 0) {
        // timeout
        std::cout << "select timeout(UDP)" << "\n" << "chang to TCP" << std::endl;
        return false;
    }
    else {
        std::cout << "call select failed(UDP)" << std::endl;
        std::cout << "change to TCP" << std::endl; 
        return false;
    }
    return true;
}

int DNS::construct_dns_message(char *domainname) {
    //
    uint16_t dns_query_type = DNS_QUERY_TYPE_A;
    if(inet_aton(domainname, nullptr) != 0) {
        // domainname is an IP addr
        dns_query_type = DNS_QUERY_TYPE_PTR;
        //this->get_correct_domainname(domainname);
    }

    // pmalloc
    int message_size = DNS_HEADER_SIZE + strlen(domainname) + 2 + DNS_QUERY_QUESTION_SIZE;
    this->_DNS_HEADER_PTR_SEND = (DNS_HEADER_PTR)malloc(message_size);
    if(this->_DNS_HEADER_PTR_SEND == nullptr) {
        std::cout << "pmalloc for DNS requested message failed!" << std::endl;
        exit(-1);
    }
    bzero(this->_DNS_HEADER_PTR_SEND, message_size);

    // set base header
    this->_DNS_HEADER_PTR_SEND->id = getpid();
    std::cout << "id:" << this->_DNS_HEADER_PTR_SEND->id << std::endl;

    this->_DNS_HEADER_PTR_SEND->flags.QR = DNS_FLAG_QR_QUERY;
    this->_DNS_HEADER_PTR_SEND->flags.opcode = DNS_FLAG_OPCODE_STANDARD_QUERY;
    this->_DNS_HEADER_PTR_SEND->flags.AA = 0;
    this->_DNS_HEADER_PTR_SEND->flags.TC = 0;
    this->_DNS_HEADER_PTR_SEND->flags.RD = 1;
    this->_DNS_HEADER_PTR_SEND->flags.RA = 0;
    this->_DNS_HEADER_PTR_SEND->flags.zero = 0;
    this->_DNS_HEADER_PTR_SEND->flags.rcode = 0;

    *(uint16_t*)&this->_DNS_HEADER_PTR_SEND->flags = htons(*(uint16_t*)&this->_DNS_HEADER_PTR_SEND->flags);

    this->_DNS_HEADER_PTR_SEND->questions = htons(1);
    this->_DNS_HEADER_PTR_SEND->answer_rrs = 0;
    this->_DNS_HEADER_PTR_SEND->authority_rrs = 0;
    this->_DNS_HEADER_PTR_SEND->aditional_rrs = 0;

    // set query name
    int pos = 0;
    this->split(domainname);
    for(auto label : this->_labels) {
        this->_DNS_HEADER_PTR_SEND->other_data[pos++] = label.length();
        //std::cout << _DNS_HEADER_PTR_SEND->other_data[pos-1];
        memcpy(&this->_DNS_HEADER_PTR_SEND->other_data[pos], label.c_str(), label.length());
        pos += label.length();
    }
    this->_DNS_HEADER_PTR_SEND->other_data[pos] = 0;

    DNS_QUERY_QUESTION_PTR DQQP = (DNS_QUERY_QUESTION_PTR)&this->_DNS_HEADER_PTR_SEND->other_data[pos+1];
    DQQP->query_type = htons(dns_query_type);
    DQQP->query_class = htons(DNS_QUERY_CALSS_IN);

    return message_size;
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



