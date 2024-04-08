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

#define MAX_QUERYS 10
#define MAX_USER_QUERYS 1024
#define MAX_DOMAIN_LENGTH 31
#define BUFFER_SIZE 1024
#define INTERFACE "enp0s1"

typedef struct {
        uint32_t size;      
        char *Domain_Name; 
}QUERY ;

typedef struct
{
    uint16_t id;             
    uint8_t Message_Type;    //  (0: QUERY, 1: RESPONSE)
    uint8_t Query_number;     //  (0-7)  
    QUERY *Queries;
} simDNSQUERY;

typedef struct
{
    uint16_t id;             
    uint8_t Message_Type; 
    uint8_t Query_number;  
}simDNSQUERYHeader;

typedef struct
{
    uint8_t Valid;     // Valid RESPONSE or not
    uint32_t IP_Addr;   
} RESPONSE;

typedef struct
{
    uint16_t id;             
    uint8_t Message_Type;  
    uint8_t Response_number; 
} SimDNSRESPONSEHeader;

typedef struct 
{
    int available;
    uint16_t id;
    simDNSQUERY QUERY;
    int Sent_C; 
} ClientQuery;

ClientQuery Queries[MAX_QUERYS];

char CLIENT_IP_ADDR[20];
char CLIENT_MAC_ADDR[30];
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

// Function to validate a domain name
int validate_domain_name(const char *domain) {
    // Check length
    size_t length = strlen(domain);
    if (length < 3 || length > MAX_DOMAIN_LENGTH) {
        return 0;
    }

    // Check characters
    for (int i = 0; i < length; i++) {
        if (!((domain[i] >= 'a' && domain[i] <= 'z') ||
              (domain[i] >= 'A' && domain[i] <= 'Z') ||
              (domain[i] >= '0' && domain[i] <= '9') ||
              (domain[i] == '-') || (domain[i] == '.'))) {
            return 0;
        }
    }

    // Check hyphens
    if (domain[0] == '-' || domain[length - 1] == '-') {
        return 0;
    }
    for (int i = 0; i < length - 1; i++) {
        if (domain[i] == '-' && domain[i + 1] == '-') {
            return 0;
        }
    }

    return 1;
}

void convert_domain_name(int32_t num, char *domain_name, char *result)
{
    result[0] = (num >> 24) & 0xFF;
    result[1] = (num >> 16) & 0xFF;
    result[2] = (num >> 8) & 0xFF;
    result[3] = num & 0xFF;

    strncpy(result + 4, domain_name, num);
}

// function to put unsigned long to a char array 
void convert_ulong_to_array(unsigned long long num, char *arr)
{
    arr[0] = (num >> 40) & 0xFF;
    arr[1] = (num >> 32) & 0xFF;
    arr[2] = (num >> 24) & 0xFF;
    arr[3] = (num >> 16) & 0xFF;
    arr[4] = (num >> 8) & 0xFF;
    arr[5] = num & 0xFF;
}

unsigned long long convert_byte_array_to_int(unsigned char *byteArray)
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

// copy two character array
void copy(char *s1, char *s2, int size)
{
    for (int i = 0; i < size; i++)
    {
        s1[i] = s2[i];
    }
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

// Function to send a DNS query
void transmit_dns_query(int sockfd, simDNSQUERY *query)
{
    unsigned char buffer[1024];

    // Set destination address and port
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ALL);
    dest_addr.sll_ifindex = if_nametoindex(INTERFACE); // replace with your network interface name
    dest_addr.sll_halen = ETH_ALEN;
    memset(dest_addr.sll_addr, 0xFF, ETH_ALEN); // destination MAC address (broadcast)

    // Prepare Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    convert_ulong_to_array(convert_mac(SERVER_MAC_ADDR), eth->h_dest);
    convert_ulong_to_array(convert_mac(CLIENT_MAC_ADDR), eth->h_source);
    eth->h_proto = htons(ETH_P_ALL); // IP protocol

    // Prepare IP header
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(0);
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->protocol = 254;     // important
    ip->saddr = inet_addr(CLIENT_IP_ADDR);     // replace with source IP
    ip->daddr = inet_addr(SERVER_IP_ADDR); // replace with destination IP
    ip->check = 0;                         // just for now, original after dataload

    // Prepare simDNS query
    simDNSQUERYHeader *packet = (simDNSQUERYHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    packet->id = query->id;
    packet->Message_Type = query->Message_Type;
    packet->Query_number = query->Query_number;

    // Preparing simDNS query part
    char *data = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQUERYHeader);
    int offset = 0;
    for (int i = 0; i < query->Query_number; i++)
    {
        char domain_i[MAX_DOMAIN_LENGTH + sizeof(int) + 2];
        convert_domain_name(query->Queries[i].size, query->Queries[i].Domain_Name, domain_i);
        copy(data + offset, domain_i, query->Queries[i].size + sizeof(int));
        offset += query->Queries[i].size + sizeof(int);
    }

    // Other IP fields
    ip->tot_len = sizeof(struct iphdr) + sizeof(simDNSQUERYHeader) + offset;
    ip->check = checksum_calc(buffer + sizeof(struct ethhdr), ip->ihl * 4);

    // Send raw packet
    int bytes_sent = sendto(sockfd, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(simDNSQUERYHeader) + offset, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == -1)
    {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}



int main(int argc, char *argv[])
{
    if(argc!=5)
    {
        fprintf(stderr, "<CLIENT MAC ADDR> <CLIENT IP ADDR> <SERVER MAC ADDR> <SERVER IP ADDR>\n");
    }
    
    strcpy(CLIENT_MAC_ADDR, argv[1]);
    strcpy(CLIENT_IP_ADDR, argv[2]);
    strcpy(SERVER_MAC_ADDR, argv[3]);
    strcpy(SERVER_IP_ADDR, argv[4]);

    int sockfd;
    struct sockaddr_ll destination_address;                 
    unsigned char buffer[BUFFER_SIZE];                   
    const char *QUERY_string = "www.computer_networks_made_easy.com"; 

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)   {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // initially free.
    for (int i = 0; i < MAX_QUERYS; i++)    {
        Queries[i].available = 1;
    }

    // Initial QUERY ID
    int present_id = 1;

    fd_set readfds;
    int max_fd_value;
    int retval;
    struct timeval  tv;

    tv.tv_sec = 3;
    tv.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        if (sockfd > STDIN_FILENO)
            max_fd_value = sockfd;
        else
            max_fd_value = STDIN_FILENO;

        retval = select(max_fd_value + 1, &readfds, NULL, NULL, &tv);

        if (retval < 0)
        {
            perror("Select error");
            exit(EXIT_FAILURE);
        }
        else if (retval == 0)
        {
            // Timeout
            for (int i = 0; i < MAX_QUERYS; i++)
            {
                if (Queries[i].available == 1)
                    continue;

                if (Queries[i].Sent_C == 4)
                {
                    printf("\n\nQuery ID: %d\n", Queries[i].id);
                    printf("Total queries (strings): %d\n\n", Queries[i].QUERY.Query_number);
                    for (int k = 0; k < Queries[i].QUERY.Query_number; k++)
                    {
                        char domain_name[MAX_DOMAIN_LENGTH + 2];
                        strncpy(domain_name, Queries[i].QUERY.Queries[k].Domain_Name, Queries[i].QUERY.Queries[k].size);
                        domain_name[Queries[i].QUERY.Queries[k].size] = '\0';
                        printf("%s\n", domain_name);
                    }
                    printf("ERROR: No response.\n\n\n");
                    Queries[i].available = 1;
                    Queries[i].Sent_C = 0;
                }
                else
                {
                    // resend queries
                    transmit_dns_query(sockfd, &(Queries[i].QUERY));
                    Queries[i].Sent_C++;
                }
            }

            tv.tv_sec = 3;
            tv.tv_usec = 0;
        }
        else
        {
            // User Input
            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                char usrQry[MAX_USER_QUERYS];
                fgets(usrQry, sizeof(usrQry), stdin);
                strtok(usrQry, "\n"); 

                int N;
                char *token = strtok(usrQry, " ");
                if (token == NULL || strcmp(token, "getIP") != 0)
                {
                    if (strcmp(token, "EXIT") == 0)
                    {
                        printf("Quitting...\n");
                        close(sockfd);
                        exit(0);
                    }
                    printf("Invalid format of Input.\n\n");
                    continue;
                }

                token = strtok(NULL, " ");
                if (token == NULL)
                {
                    printf("Invalid format of Input.\n\n");
                    continue;
                }

                N = atoi(token);
                if (N <= 0 || N > 8)
                {
                    printf("Invalid N.\n\n");
                    continue;
                }

                // Extract domain names
                char domains[N][MAX_DOMAIN_LENGTH + 1];
                int flag_Correct = 1;
                for (int i = 0; i < N; i++)
                {
                    token = strtok(NULL, " ");
                    if (token == NULL)
                    {
                        printf("Less Domain names, compared to N.\n\n");
                        flag_Correct = 0;
                        break;
                    }
                    else if (validate_domain_name(token) == 0)
                    {
                        printf("Invalid Domain Name.\n\n");
                        flag_Correct = 0;
                        break;
                    }
                    else
                    {
                        strcpy(domains[i], token); // Allocate memory and copy domain name
                    }
                }
                if (!flag_Correct)
                    continue;

                int free_idx = -1;
                for (int j = 0; j < MAX_QUERYS; j++)
                {
                    if (Queries[j].available)
                    {
                        free_idx = j;
                        Queries[j].available = 0;
                        break;
                    }
                }

                if (free_idx == -1)
                {
                    printf("Wait for sometime.. \n\n");
                    continue;
                }

                // update query table
                Queries[free_idx].id = present_id;
                Queries[free_idx].Sent_C = 1;
                Queries[free_idx].QUERY.id = present_id;
                Queries[free_idx].QUERY.Message_Type = 0;
                Queries[free_idx].QUERY.Query_number = N;
                Queries[free_idx].QUERY.Queries = (QUERY *)malloc(N * sizeof(QUERY));
                for (int j = 0; j < N; j++)
                {
                    Queries[free_idx].QUERY.Queries[j].size = strlen(domains[j]);
                    Queries[free_idx].QUERY.Queries[j].Domain_Name = (char *)malloc(strlen(domains[j]) * sizeof(char));
                    strncpy(Queries[free_idx].QUERY.Queries[j].Domain_Name, domains[j], strlen(domains[j]));
                }
                present_id = (present_id + 1) % 65536;
                transmit_dns_query(sockfd, &(Queries[free_idx].QUERY));
            }
            // Message is response
            else if (FD_ISSET(sockfd, &readfds))
            {
                unsigned int my_ip_addr = convert_ip(CLIENT_IP_ADDR);
                unsigned long long my_mac_addr = convert_mac(CLIENT_MAC_ADDR);
                unsigned long long broadcast_mac_addr = 0xFFFFFFFFFFFFULL;

                // Receive packet
                struct sockaddr_in local_addr;
                socklen_t local_addr_len = sizeof(local_addr);
                int packet_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&local_addr, &local_addr_len);

                if (packet_len == -1)
                {
                    perror("recvfrom");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }

                // Parse Ethernet header
                struct ethhdr *eth = (struct ethhdr *)buffer;
                if (ntohs(eth->h_proto) != ETH_P_ALL)
                {
                    continue;
                }

                if (convert_byte_array_to_int(eth->h_dest) != convert_mac(CLIENT_MAC_ADDR) && convert_byte_array_to_int(eth->h_dest) != convert_mac("ff:ff:ff:ff:ff:ff"))
                {
                    continue;
                }

                // Parse IP header
                struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

                int prev_checksum = ip->check;
                ip->check = 0;
                int curr_checksum = checksum_calc(buffer + sizeof(struct ethhdr), ip->ihl * 4);
                if (prev_checksum != curr_checksum)
                {
                    continue;
                }
                ip->check = curr_checksum;

                if (ip->protocol != 254 || (ip->daddr != my_ip_addr && ip->saddr != ip->daddr))
                {
                    continue;
                }

                SimDNSRESPONSEHeader *header = (SimDNSRESPONSEHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
                char *DNSdata = (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(SimDNSRESPONSEHeader));

                int id = header->id;
                int messageType = header->Message_Type;

                if (messageType != 1)
                    continue;

                int flag_idpresent = 0;
                int qry_id = -1;
                int ndomain = 0;
                int idx = 0;
                for (idx = 0; idx < MAX_QUERYS; idx++)
                {
                    if (Queries[idx].available == 1)
                        continue;
                    if (Queries[idx].id == id && Queries[idx].Sent_C > 0)
                    {
                        flag_idpresent = 1;
                        ndomain = Queries[idx].QUERY.Query_number;
                        qry_id = Queries[idx].QUERY.id;
                        break;
                    }
                }
                if (!flag_idpresent)
                    continue;

                printf("\n\nQuery ID: %d\n", qry_id);
                printf("Total queries (strings): %d\n\n", ndomain);
                for (int k = 0; k < ndomain; k++)
                {
                    char domain_name[MAX_DOMAIN_LENGTH + 2];
                    strncpy(domain_name, Queries[idx].QUERY.Queries[k].Domain_Name, Queries[idx].QUERY.Queries[k].size);
                    domain_name[Queries[idx].QUERY.Queries[k].size] = '\0';

                    RESPONSE *response_k = (RESPONSE *)(DNSdata + k * sizeof(RESPONSE));
                    if (response_k->Valid == 0)
                    {
                        printf("%-31s   %-31s\n", domain_name, "NO IP ADDRESS FOUND");
                    }
                    else
                    {
                        struct in_addr addr;
                        addr.s_addr = response_k->IP_Addr;
                        printf("%-31s   %-31s\n", domain_name, inet_ntoa(addr));
                    }
                }
                printf("\n\n");

                Queries[idx].available = 1;
                Queries[idx].Sent_C = 0;
            }
        }
    }
}
