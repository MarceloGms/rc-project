#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFFER_SIZE 1024

int end = 0;
pthread_t receiveThreadId[5];
int n_subs = 0;

void erro(char *msg);

void* receiveThread(void* arg) {
    char* multicastAddress = (char*)arg;
    int sock;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(multicastAddress);
    addr.sin_port = htons(5000);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(multicastAddress);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    while (1) {
        if (end == 1) {
            break;
        }

        ssize_t numBytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (numBytes < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            }
            perror("recv");
            exit(1);
        }
        buffer[numBytes] = '\0';
        printf("%s\n", buffer);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
  char endServer[100];
  int fd;
  struct sockaddr_in addr;
  struct hostent *hostPtr;

  if (argc != 3) {
    printf("news_client <endereço do server> <PORTO_NOTICIAS>\n");
    exit(-1);
  }

  strcpy(endServer, argv[1]);
  if ((hostPtr = gethostbyname(endServer)) == 0)
    erro("Não consegui obter endereço");

  bzero((void *) &addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ((struct in_addr *)(hostPtr->h_addr))->s_addr;
  addr.sin_port = htons((short) atoi(argv[2]));

  if ((fd = socket(AF_INET,SOCK_STREAM,0)) == -1)
      erro("socket");
  if (connect(fd,(struct sockaddr *)&addr,sizeof (addr)) < 0)
      erro("Connect");

  char buff[BUFFER_SIZE];
  char quit[BUFFER_SIZE];
  while(1){
  	
      fgets(buff, BUFFER_SIZE, stdin);
      strcpy(quit, buff);
      write(fd, buff, strlen(buff));

      bzero(buff, BUFFER_SIZE);    
      ssize_t numBytes = read(fd, buff, sizeof(buff) - 1);
      if (numBytes < 0) {
            perror("TCP receive error");
            exit(EXIT_FAILURE);
      }
      buff[numBytes] = '\0';
      char* trimmedBuffer = buff;
    	while (isspace(*trimmedBuffer))
        	trimmedBuffer++;
	
    	size_t length = strlen(trimmedBuffer);
    	while (length > 0 && isspace(trimmedBuffer[length - 1]))
        	trimmedBuffer[--length] = '\0';
      printf("%s\n", trimmedBuffer);        
      bzero(buff, BUFFER_SIZE);
      
      if (strstr(trimmedBuffer, "MULTICAST:") != NULL) {
      	if (n_subs < 5){
      	char *multicastAddr = strtok(trimmedBuffer, ":");
      	multicastAddr = strtok(NULL, " ");
    	if (pthread_create(&receiveThreadId[n_subs], NULL, receiveThread, (void*)multicastAddr) != 0) {
        	perror("pthread_create");
        	exit(1);
    	}
    	n_subs++;
    	} else printf("max number of subscriptions reached\n");
    	}
      	
      if (strcmp(quit, "QUIT\n") == 0){
		end = 1;
          break;
      }
  }
  for (int i = 0; i < n_subs; i++){
  if (pthread_join(receiveThreadId[i], NULL) != 0) {
        perror("pthread_join");
        exit(1);
    }
    }
  close(fd);
  exit(0);
}
void erro(char *msg) {
  printf("Erro: %s\n", msg);
  exit(-1);
}
