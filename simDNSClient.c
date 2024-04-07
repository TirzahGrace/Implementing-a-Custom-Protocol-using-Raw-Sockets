#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <errno.h>
#include <sys/select.h>

#define BUF_SIZE 1024
#define PROTOCOL_SIMDNS 254
#define MAX_DOMAINS 8
#define MAX_DOMAIN_NAME_LENGTH 31
#define RETRY_LIMIT 3

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

// Function to validate domain name format
int validate_domain_name(const char *domain) {
    // Check length
    size_t length = strlen(domain);
    if (length < 3 || length > MAX_DOMAIN_NAME_LENGTH)
        return 0;

    // Check characters
    for (int i = 0; i < length; i++) {
        if (!((domain[i] >= 'a' && domain[i] <= 'z') ||
              (domain[i] >= 'A' && domain[i] <= 'Z') ||
              (domain[i] >= '0' && domain[i] <= '9') ||
              domain[i] == '-' ||
              (i > 0 && i < length - 1 && domain[i] == '.')))
            return 0;
    }

    // Check consecutive hyphens
    for (int i = 0; i < length - 1; i++) {
        if (domain[i] == '-' && domain[i + 1] == '-')
            return 0;
    }

    return 1;
}

// Function to send simDNS query
void send_query(const char *server_ip, unsigned short query_id, unsigned char num_queries, char *queries[]) {
    struct sockaddr_in server_addr;
    int sockfd, ret;

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Construct server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Construct simDNS Query packet
    struct simDNSQuery query;
    memset(&query, 0, sizeof(query));
    query.id = query_id;
    query.message_type = 0; // Query
    query.num_queries = num_queries;
    for (int i = 0; i < num_queries; i++) {
        query.queries[i].domain_size = strlen(queries[i]);
        strcpy(query.queries[i].domain, queries[i]);
    }

    // Send query
    ret = sendto(sockfd, &query, sizeof(query), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    char input[BUF_SIZE];
    fd_set readfds;
    int sockfd, max_fd, ret, query_id = 0;
    struct timeval timeout;
    unsigned char buffer[BUF_SIZE];

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Wait for user input
        printf("Enter query string (or 'EXIT' to quit): ");
        if (fgets(input, BUF_SIZE, stdin) == NULL) {
            perror("Failed to read input");
            exit(EXIT_FAILURE);
        }

        // Remove newline character
        input[strcspn(input, "\n")] = '\0';

        // Check if user wants to exit
        if (strcmp(input, "EXIT") == 0) {
            break;
        }

        // Parse input query
        char *token = strtok(input, " ");
        if (token == NULL || strcmp(token, "getIP") != 0) {
            fprintf(stderr, "Invalid query format\n");
            continue;
        }

        token = strtok(NULL, " ");
        if (token == NULL) {
            fprintf(stderr, "Missing number of queries\n");
            continue;
        }

        int num_queries = atoi(token);
        if (num_queries < 1 || num_queries > MAX_DOMAINS) {
            fprintf(stderr, "Number of queries should be between 1 and %d\n", MAX_DOMAINS);
            continue;
        }

        char *queries[MAX_DOMAINS];
        for (int i = 0; i < num_queries; i++) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                fprintf(stderr, "Missing query domain\n");
                break;
            }

            if (!validate_domain_name(token)) {
                fprintf(stderr, "Invalid domain name: %s\n", token);
                break;
            }

            queries[i] = token;
        }

        if (num_queries == 0) {
            continue;
        }

        // Send query
        send_query(server_ip, query_id++, num_queries, queries);

        // Wait for response
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        max_fd = sockfd + 1;
        timeout.tv_sec = 5; // 5-second timeout
        timeout.tv_usec = 0;

        ret = select(max_fd, &readfds, NULL, NULL, &timeout);
        if (ret == -1) {
            perror("Select error");
            exit(EXIT_FAILURE);
        } else if (ret == 0) {
            fprintf(stderr, "Timeout occurred, no response received\n");
            continue;
        }

        // Read response
        ssize_t bytes_received = recv(sockfd, buffer, BUF_SIZE, 0);
        if (bytes_received < 0) {
            perror("Recv error");
            exit(EXIT_FAILURE);
        }

        // Process response (not implemented in this example)
        printf("Received response\n");
    }

    close(sockfd);
    return 0;
}
