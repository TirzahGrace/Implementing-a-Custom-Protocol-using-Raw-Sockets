#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#define SERVER_PORT 9009
#define CLIENT_PORT 8992
#define MAXLINE 1000

void clearBuf(char* b)
{
    int i;
    for (i = 0; i < 1024; i++)
        b[i] = '\0';
}

int main()
{
    // Create socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        printf("Error creating socket\n");
        exit(EXIT_FAILURE);
    }

    // Configure the server and current address
    struct sockaddr_in server, client;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(SERVER_PORT);

    client.sin_family = AF_INET;
    client.sin_addr.s_addr = INADDR_ANY;
    client.sin_port = htons(CLIENT_PORT);

    // Bind the socket to the address
    if( bind(sockfd, (const struct sockaddr *)&client, sizeof(client)) < 0)
    {
        printf("Bind failure\n");
        exit(EXIT_FAILURE);
    }

    
  while(1)
  {
    // Get the domain name for query
      char send_b[MAXLINE], recv_b[MAXLINE];
      printf("Enter the DNS: ");
      getchar();
      scanf("%[^\n]",send_b); 
      printf("DNS is: %s\n",send_b);
      sendto(sockfd, send_b, sizeof(send_b), 0,(const struct sockaddr *)&server, (socklen_t)sizeof(server));
      printf("Addresses are:\n");
      socklen_t addr_size;
      addr_size = sizeof(client);
      recvfrom(sockfd, recv_b, 1000, 0,(struct sockaddr*)&client,&addr_size);
      printf("%s\n",recv_b);
      if (strcmp(recv_b, "") == 0) {
        // recv_b is an empty string
        break;
      }
    clearBuf(recv_b);
  }
  close(sockfd);
}