#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <ctype.h>
#include <time.h>
#include <netdb.h>

#define DROP_PROBABILITY 0.2
#define MAX_QUERYS 10
#define MAX_USER_QUERYS 1024
#define MAX_DOMAIN_LENGTH 31
#define BUFFER_SIZE 1024
#define INTERFACE "enp0s1"

typedef struct
{
    uint16_t id;             
    uint8_t Message_Type; 
    uint8_t Query_number;  
}simDNSQUERYHeader;

typedef struct
{
    uint8_t Valid;     
    uint32_t IP_Addr;   
} RESPONSE;

typedef struct
{
    uint16_t id;             
    uint8_t Message_Type;  
    uint8_t Response_number; 
} SimDNSRESPONSEHeader;

char SERVER_IP_ADDR[20];
char SERVER_MAC_ADDR[30];


uint32_t convert_ip(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 0;
    }
    return addr.s_addr;
}

unsigned long long convert_mac(const char *mac_str)
{
    unsigned long long mac_int = 0;
    int i;

    for (i = 0; i < 17; i += 3)
    {
        unsigned int byte;
        sscanf(mac_str + i, "%2x", &byte);
        mac_int = (mac_int << 8) | byte;
    }

    return mac_int;
}

// copy two character array
void copy(char *s1, char *s2, int size)
{
    for (int i = 0; i < size; i++)
    {
        s1[i] = s2[i];
    }
}

void convert_ulong_to_array(unsigned long long num, char *arr)
{
    arr[0] = (num >> 40) & 0xFF;
    arr[1] = (num >> 32) & 0xFF;
    arr[2] = (num >> 24) & 0xFF;
    arr[3] = (num >> 16) & 0xFF;
    arr[4] = (num >> 8) & 0xFF;
    arr[5] = num & 0xFF;
}

int32_t convert_byte_array_to_int32(unsigned char *byteArray)
{
    int32_t num = 0;

    num |= ((int32_t)byteArray[0] << 24);
    num |= ((int32_t)byteArray[1] << 16);
    num |= ((int32_t)byteArray[2] << 8);
    num |= (int32_t)byteArray[3];

    return num;
}

unsigned long long convert_byte_array_to_int48(unsigned char *byteArray)
{
    unsigned long long num = 0;

    num |= ((unsigned long long)byteArray[0] << 40);
    num |= ((unsigned long long)byteArray[1] << 32);
    num |= ((unsigned long long)byteArray[2] << 24);
    num |= ((unsigned long long)byteArray[3] << 16);
    num |= ((unsigned long long)byteArray[4] << 8);
    num |= (unsigned long long)byteArray[5];

    return num;
}

uint32_t get_ip_from_host(char *host)
{
    struct hostent *host_info;
    host_info = gethostbyname(host);
    if (host_info == NULL) return 0;
    struct in_addr addr;
    memcpy(&addr, host_info->h_addr_list[0], sizeof(struct in_addr));
    uint32_t ip = addr.s_addr;
    return ip;
}

uint16_t checksum_calc(const char *buffer, size_t length) {
    uint32_t sum = 0;
    const uint16_t *data = (const uint16_t *)buffer;

    while (length > 1) {
        sum += *data;
        data++;
        length -= 2;
    }

    if (length == 1) {
        const uint8_t *last_byte = (const uint8_t *)data;
        sum += *last_byte;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}


void send_response(int sockfd, char *DNSquerydata, simDNSQUERYHeader *query_header, int32_t cli_ip, unsigned long long cli_mac)
{
    char buffer[1024];

    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex(INTERFACE); 
    dest_addr.sll_halen = ETH_ALEN;
    memset(dest_addr.sll_addr, 0xFF, ETH_ALEN); 

    struct ethhdr *eth = (struct ethhdr *)buffer;
    convert_ulong_to_array(cli_mac, eth->h_dest);
    convert_ulong_to_array(convert_mac(SERVER_MAC_ADDR), eth->h_source);
    eth->h_proto = htons(ETH_P_ALL);       

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(0);
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->protocol = 254;
    ip->saddr = inet_addr(SERVER_IP_ADDR);       
    ip->daddr = cli_ip; 
    ip->check = 0; 

    SimDNSRESPONSEHeader *response_header = (SimDNSRESPONSEHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    response_header->id = query_header->id;
    response_header->Message_Type = 1;
    response_header->Response_number = query_header->Query_number;

    int offset = 0;
    for (int i = 0; i < response_header->Response_number; i++)
    {
        int domain_length = convert_byte_array_to_int32(DNSquerydata + offset);
        char domain[MAX_DOMAIN_LENGTH + 1];
        copy(domain, DNSquerydata + offset + sizeof(int), domain_length);

        offset += domain_length + sizeof(int);

        domain[domain_length] = '\0';
        uint32_t ip = get_ip_from_host(domain);

        RESPONSE *response_i = (RESPONSE *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSRESPONSEHeader) + i * sizeof(RESPONSE));

        if (ip == 0)
        {
            response_i->Valid = 0;
        }
        else
        {
            response_i->Valid = 1;
        }
        response_i->IP_Addr = ip;
    }

    ip->tot_len = sizeof(struct iphdr) + sizeof(SimDNSRESPONSEHeader) + response_header->Response_number * sizeof(RESPONSE);
    ip->check = checksum_calc(buffer + sizeof(struct ethhdr), ip->ihl * 4);

    int bytes_sent = sendto(sockfd, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSRESPONSEHeader) + response_header->Response_number * sizeof(RESPONSE), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == -1)
    {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

int drop_Message_with_probability(float p)
{
    float number = (float)(rand() % 1000) / 1000;

    if (number < p) return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    if(argc!=3)
    {
        fprintf(stderr, "<SERVER MAC ADDR> <SERVER IP ADDR> \n");
    }

    strcpy(SERVER_MAC_ADDR, argv[1]);
    strcpy(SERVER_IP_ADDR, argv[2]);

    unsigned int my_ip_addr = convert_ip(SERVER_IP_ADDR);
    unsigned long long my_mac_addr = convert_mac(SERVER_MAC_ADDR);
    unsigned long long broadcast_mac_addr = 0xFF;
    int sockfd;
    struct sockaddr_in local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    unsigned char buffer[65536];           
    const char *interface_name = INTERFACE; 

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1)
    {
        perror("setsockopt");
        fprintf(stderr, "Error code: %d\n", errno);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Bound\n");

    while (1)
    {
        // Receive packet
        int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&local_addr, &local_addr_len);
        if (packet_len == -1)
        {
            perror("recvfrom");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if(drop_Message_with_probability((float)DROP_PROBABILITY)==1) continue;

        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        if (ntohs(eth_header->h_proto) != ETH_P_ALL) continue;

        unsigned long long int eth_header_dest = convert_byte_array_to_int48(eth_header->h_dest);
        unsigned long long int eth_header_src = convert_byte_array_to_int48(eth_header->h_source);

        struct iphdr *IP_Header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        int previous_checksum = IP_Header->check;
        IP_Header->check = 0;
        int curr_checksum = checksum_calc(buffer + sizeof(struct ethhdr), IP_Header->ihl * 4);

        if (previous_checksum != curr_checksum) continue;
        IP_Header->check = curr_checksum;
        if (IP_Header->protocol != 254) continue;
        if (IP_Header->daddr != my_ip_addr && IP_Header->saddr != IP_Header->daddr) continue;

        simDNSQUERYHeader *DNS_Header = (simDNSQUERYHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (DNS_Header->Message_Type != 0) continue;
        char *DNS_Data = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQUERYHeader);
        send_response(sockfd, DNS_Data, DNS_Header, IP_Header->saddr, eth_header_src);
    }

    close(sockfd);
    return 0;
}
