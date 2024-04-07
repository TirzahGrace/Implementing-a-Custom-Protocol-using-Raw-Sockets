#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
struct hostent *he;
struct in_addr **addr_list;
struct in_addr addr;

void clearBuf(char* b)
{
    int i;
    for (i = 0; i < 1024; i++)
        b[i] = '\0';
}

int main(int argc, char **argv){

  if(argc != 2){
    printf("Usage: %s <port>\n", argv[0]);
    exit(0);
  }
  int i;
  int port = atoi(argv[1]);
  int sockfd;
  struct sockaddr_in si_me, si_other;
  char buffer[1024];
  socklen_t addr_size;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  memset(&si_me, '\0', sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(port);
  si_me.sin_addr.s_addr = inet_addr("127.0.0.1");

  bind(sockfd, (struct sockaddr*)&si_me, sizeof(si_me));
  addr_size = sizeof(si_other);

  while(1){
  recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr*)& si_other, &addr_size);
  printf("[+]Data Received: %s\n", buffer);
  char buffer1[1024];
  he = gethostbyname(buffer);
  if(he == NULL) 
  { // do some error checking
    strcpy(buffer1,"0.0.0.0");
    sendto(sockfd, buffer1, 1024, 0, (struct sockaddr*)&si_other, sizeof(si_other));
  }
  else {
  addr_list = (struct in_addr **)he->h_addr_list;
  /*
  for(i = 0; addr_list[i] != NULL; i++) 
  {
    strcpy(buffer1,inet_ntoa(*addr_list[i]));
    sendto(sockfd, buffer1, 1024, 0, (struct sockaddr*)&si_other, sizeof(si_other));
    clearBuf(buffer1);
  }
  */
    strcpy(buffer1,inet_ntoa(*addr_list[0]));
    sendto(sockfd, buffer1, 1024, 0, (struct sockaddr*)&si_other, sizeof(si_other));
    clearBuf(buffer1);
    /*
    strcpy(buffer1," ");
    sendto(sockfd, buffer1, 1024, 0, (struct sockaddr*)&si_other, sizeof(si_other));
    */
  }
  }
  return 0;
}