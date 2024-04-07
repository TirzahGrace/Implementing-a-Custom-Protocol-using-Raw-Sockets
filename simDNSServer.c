#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if_ether.h> 

#define BUF_SIZE 1024
#define PROTOCOL_SIMDNS 254
#define MAX_DOMAINS 8
#define MAX_DOMAIN_NAME_LENGTH 31

// Structure for simDNS Query packet
struct simDNSQuery {
    unsigned short id;
    unsigned char message_type;
    unsigned char num_queries;
    struct {
        unsigned int domain_size;
        char domain[MAX_DOMAIN_NAME_LENGTH + 1];
    } queries[MAX_DOMAINS];
};

// Structure for simDNS Response packet
struct simDNSResponse {
    unsigned short id;
    unsigned char message_type;
    unsigned char num_responses;
    struct {
        unsigned char flag;
        struct in_addr ip_address;
    } responses[MAX_DOMAINS];
};

// Function to parse the received query and generate response
void parse_query_and_respond(unsigned char *buffer, int query_len, struct sockaddr_in *client_addr, socklen_t addr_len) {
    // Parse simDNS Query packet
    struct simDNSQuery *query = (struct simDNSQuery *)buffer;

    // Prepare simDNS Response packet
    struct simDNSResponse response;
    memset(&response, 0, sizeof(response));
    response.id = query->id;
    response.message_type = 1; // Response

    // Resolve domain names to IP addresses and populate response
    response.num_responses = query->num_queries;
    for (int i = 0; i < query->num_queries; i++) {
        struct hostent *host = gethostbyname(query->queries[i].domain);
        if (host == NULL || host->h_addr_list[0] == NULL) {
            response.responses[i].flag = 0; // Invalid response
        } else {
            response.responses[i].flag = 1; // Valid response
            memcpy(&response.responses[i].ip_address, host->h_addr_list[0], sizeof(struct in_addr));
        }
    }

    // Send response to the client
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (sendto(sockfd, &response, sizeof(response), 0, (struct sockaddr *)client_addr, addr_len) < 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

int main() {
    int sockfd, bytes_received;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Step 1: Open a raw socket to capture all packets till Ethernet
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Step 2: Bind socket to local IP address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Receive packets and respond
    while (1) {
        bytes_received = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (bytes_received < 0) {
            perror("Recvfrom failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        
        // Check if it's a simDNS query (protocol field 254)
        struct iphdr *ip = (struct iphdr *)buffer;
        if (ip->protocol == PROTOCOL_SIMDNS) {
            // Parse query and generate response
            parse_query_and_respond(buffer + sizeof(struct iphdr), bytes_received - sizeof(struct iphdr), &client_addr, addr_len);
        }
    }

    close(sockfd);
    return 0;
}
