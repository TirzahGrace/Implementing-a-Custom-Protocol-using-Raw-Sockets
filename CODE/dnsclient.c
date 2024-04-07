#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<sys/select.h>
#include<sys/time.h>

#define SERVER_PORT 9009
#define CLIENT_PORT 8992
#define MAXLINE 1000
#define MAX_QUERIES 8
#define MAX_DOMAIN_LENGTH 31

// Structure for simDNS Query packet
struct simDNSQuery {
    unsigned short id;
    unsigned char message_type; // 0: Query, 1: Response
    unsigned char num_queries; // Number of queries (3 bits)
    struct {
        unsigned int domain_size; // Size of domain name in characters
        char domain[MAX_DOMAIN_LENGTH + 1]; // Actual domain name
    } queries[MAX_QUERIES];
};

// Structure for simDNS Response packet
struct simDNSResponse {
    unsigned short id;
    unsigned char message_type; // 0: Query, 1: Response
    unsigned char num_responses; // Number of responses (3 bits)
    struct {
        unsigned char flag; // Flag indicating if it's a valid response (1: Valid, 0: Invalid)
        struct in_addr ip_address; // IP address corresponding to the domain
    } responses[MAX_QUERIES];
};

// Structure for pending query table entry
struct PendingQuery {
    unsigned short id;
    int retries;
};

// Function to construct and send simDNS query packet
void send_query_packet(int sockfd, struct sockaddr_in *server_addr, struct simDNSQuery *query) {
    sendto(sockfd, query, sizeof(struct simDNSQuery), 0, (const struct sockaddr *)server_addr, sizeof(struct sockaddr_in));
}

// Function to handle simDNS responses
void handle_response(struct simDNSResponse *response) {
    printf("Query ID: %d\n", response->id);
    printf("Total query strings: %d\n", response->num_responses);
    for (int i = 0; i < response->num_responses; i++) {
        printf("%s ", inet_ntoa(response->responses[i].ip_address));
        printf("%s\n", response->responses[i].flag ? "Valid" : "NO IP ADDRESS FOUND");
    }
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

int main() {
    // Create socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Configure the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // Initialize the pending query table
    struct PendingQuery pending_queries[MAX_QUERIES];
    int num_pending_queries = 0;

    // Bind the socket to the client address
    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(CLIENT_PORT);
    if (bind(sockfd, (const struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Bind failure");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Get input from the user
        printf("Enter the DNS query: ");
        char query[MAXLINE];
        fgets(query, MAXLINE, stdin);
        strtok(query, "\n"); // Remove newline character

        // Check for EXIT command
        if (strcmp(query, "EXIT") == 0) {
            close(sockfd);
            exit(EXIT_SUCCESS);
        }

        // Parse input and construct simDNS query packet
        struct simDNSQuery sim_query;
        memset(&sim_query, 0, sizeof(sim_query));
        sim_query.id = rand() % 65536; // Unique ID for each query
        sim_query.message_type = 0; // Query
        char *token = strtok(query, " ");
        if (strcmp(token, "getIP") != 0) {
            printf("Invalid command\n");
            continue;
        }
        token = strtok(NULL, " ");
        int num_queries = atoi(token);
        if (num_queries < 1 || num_queries > MAX_QUERIES) {
            printf("Invalid number of queries\n");
            continue;
        }
        sim_query.num_queries = num_queries;
        for (int i = 0; i < num_queries; i++) {
            token = strtok(NULL, " ");
            if (!validate_domain_name(token)) {
                printf("Invalid domain name: %s\n", token);
                continue;
            }
            sim_query.queries[i].domain_size = strlen(token);
            strncpy(sim_query.queries[i].domain, token, MAX_DOMAIN_LENGTH);
        }

        // Send simDNS query packet
        send_query_packet(sockfd, &server_addr, &sim_query);

        // Add query to pending query table
        pending_queries[num_pending_queries].id = sim_query.id;
        pending_queries[num_pending_queries].retries = 0;
        num_pending_queries++;

        // Use select to wait for response or timeout
        fd_set rfds;
        struct timeval tv;
        int retval;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        tv.tv_sec = 5; // Timeout of 5 seconds
        tv.tv_usec = 0;
        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
        } else if (retval) {
            // Response received
            struct simDNSResponse sim_response;
            recvfrom(sockfd, &sim_response, sizeof(sim_response), 0, NULL, NULL);
            handle_response(&sim_response);
            // Remove query from pending query table
            for (int i = 0; i < num_pending_queries; i++) {
                if (pending_queries[i].id == sim_response.id) {
                    // Shift remaining queries to fill the gap
                    for (int j = i; j < num_pending_queries - 1; j++) {
                        pending_queries[j] = pending_queries[j + 1];
                    }
                    num_pending_queries--;
                    break;
                }
            }
        } else {
            // Timeout
            printf("Timeout: No response received\n");
            // Retry logic can be added here
        }
    }

    return 0;
}
