#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUF_SIZE 1024
#define MAX_DOMAIN_LENGTH 31

struct hostent *he;
struct in_addr **addr_list;

// Structure for simDNS Query packet
struct simDNSQuery {
    unsigned short id;
    unsigned char message_type; // 0: Query, 1: Response
    unsigned char num_queries; // Number of queries (3 bits)
    struct {
        unsigned int domain_size; // Size of domain name in characters
        char domain[MAX_DOMAIN_LENGTH + 1]; // Actual domain name
    } queries[8];
};

// Structure for simDNS Response packet
struct simDNSResponse {
    unsigned short id;
    unsigned char message_type; // 0: Query, 1: Response
    unsigned char num_responses; // Number of responses (3 bits)
    struct {
        unsigned char flag; // Flag indicating if it's a valid response (1: Valid, 0: Invalid)
        struct in_addr ip_address; // IP address corresponding to the domain
    } responses[8];
};

// Function to clear buffer
void clearBuf(char* b)
{
    int i;
    for (i = 0; i < 1024; i++)
        b[i] = '\0';
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int sockfd;
    struct sockaddr_in si_me, si_other;
    char buffer[BUF_SIZE];
    socklen_t addr_size = sizeof(si_other);

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&si_me, sizeof(si_me)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while(1) {
        struct simDNSQuery *query = malloc(sizeof(struct simDNSQuery)); // Allocate memory for query
        recvfrom(sockfd, query, sizeof(struct simDNSQuery), 0, (struct sockaddr*)&si_other, &addr_size);
        printf("[+]Data Received: query id: %d\n", query->id);

        struct simDNSResponse response;
        memset(&response, 0, sizeof(response));
        response.id = query->id;
        response.message_type = 1; // Response
        response.num_responses = query->num_queries; // Set number of responses same as number of queries

        // Process each query
        for (int i = 0; i < query->num_queries; i++) {
            printf("id: %d -> query: %d: %s\n", response.id, i, query->queries[i].domain);
            he = gethostbyname(query->queries[i].domain);
            if (he == NULL) { 
                response.responses[i].flag = 0;
                response.responses[i].ip_address.s_addr = inet_addr("0.0.0.0");
            } else {
                addr_list = (struct in_addr **)he->h_addr_list;
                response.responses[i].flag = 1;
                response.responses[i].ip_address = *addr_list[0]; // Set IP address directly
            }
        }

        // Send response
        sendto(sockfd, &response, sizeof(response), 0, (struct sockaddr*)&si_other, addr_size);

        // Clear buffer
        clearBuf(buffer);
        free(query); // Free memory allocated for query
    }

    close(sockfd);
    return 0;
}
