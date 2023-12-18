#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>

#define BUFLEN 100
#define MAX_IPS 7
#define MAX_CLIENTS 5

char ips[MAX_IPS][INET_ADDRSTRLEN];
int udpSocket, tcpSocket, tcpClient;
struct sockaddr_in serverAddressUdp, serverAddressTcp, tcpClientAddress;
pthread_t tcpThread[MAX_CLIENTS], udpThread;
int num_ips = 0;
const char *file;
int end = 0;
int num_clients=0;
pthread_mutex_t ipsMutex, clientMutex, adminMutex;

struct ClientInfo {
    int socket;
    struct sockaddr_in address;
};

typedef struct{
    char topic_id[200];
    char topic_tit[200];
    char topic_addr[200];
}Topic_Struct;

Topic_Struct topicos[10];

Topic_Struct null_topico = {"", "", ""};

void erro(char *s) {
	perror(s);
	exit(1);
	}
	
void clean_resources(){
	for (int i = 0; i < num_clients; i++) {
        pthread_join(tcpThread[i], NULL);
    }
    pthread_join(udpThread, NULL);
    pthread_mutex_destroy(&ipsMutex);
    pthread_mutex_destroy(&clientMutex);
    pthread_mutex_destroy(&adminMutex);

	close(udpSocket);
  	close(tcpSocket);
}

void sigint_handler(int signum){
	end = 1;
	clean_resources();
	exit(0);
}

char* generateMulticastAddress(const char* topic) {
    unsigned int baseAddress = 0xE0000000;  // 224.0.0.0

    unsigned long hash = 5381;
    int c;
    while ((c = *topic++)) {
        hash = ((hash << 5) + hash) + c;
    }

    unsigned int multicastAddress = baseAddress | (hash & 0x00FFFFFF);

    char* addressString = (char*)malloc(16 * sizeof(char));
    snprintf(addressString, 16, "%u.%u.%u.%u",
             (multicastAddress >> 24) & 0xFF,
             (multicastAddress >> 16) & 0xFF,
             (multicastAddress >> 8) & 0xFF,
             multicastAddress & 0xFF);

    return addressString;
}

void sendMulticastMessage(const char *multicastAddr, const char *message) {
    int multiSock;
    if ((multiSock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in multiAddr;
    memset(&multiAddr, 0, sizeof(multiAddr));
    multiAddr.sin_family = AF_INET;
    multiAddr.sin_addr.s_addr = inet_addr(multicastAddr);
    multiAddr.sin_port = htons(5000);

    int enable = 2;
    if (setsockopt(multiSock, IPPROTO_IP, IP_MULTICAST_TTL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    ssize_t numBytes = sendto(multiSock, message, strlen(message), 0, (struct sockaddr *)&multiAddr, sizeof(multiAddr));
    if (numBytes < 0) {
        perror("sendto");
        exit(1);
    }

    close(multiSock);
}

void add_user(char *username, char *password, char *type, struct sockaddr_in clientAddress, socklen_t addrLen){
	FILE *fp = fopen("users.txt", "a+");
    if (fp == NULL) {
        printf("Error opening file\n");
        return;
    }
    
    char line[100];
    while (fgets(line, 100, fp) != NULL) {
    	if(strcmp(strtok(line, ";"), username) == 0){
    		sendto(udpSocket, "username already exists!\n", strlen("username already exists!\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
    		return;
    	}
    }
	
	sendto(udpSocket, "OK\n", strlen("OK\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
    fprintf(fp, "%s;%s;%s\n", username, password, type);
    fclose(fp);
}

void remove_user(char *username, struct sockaddr_in clientAddress, socklen_t addrLen){
	FILE *input_file = fopen("users.txt", "r");
	FILE *output_file = fopen("temp.txt", "w");
	
	if (input_file == NULL || output_file == NULL) {
    	printf("Error opening file\n");
    	exit(1);
	}
	
	char buffer[100], aux[100];
	while (fgets(buffer, 100, input_file)) {
		strcpy(aux, buffer);
    	if (strcmp(strtok(buffer, ";"), username) != 0){
        	fprintf(output_file, "%s", aux);
    	}
	}
	
	fclose(input_file);
	fclose(output_file);
	
	if (remove("users.txt") != 0) {
    	printf("Error deleting file\n");
    	exit(1);
	}
	if (rename("temp.txt", "users.txt") != 0) {
    	printf("Error renaming file\n");
    	exit(1);
	}
	sendto(udpSocket, "OK\n", strlen("OK\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
}

void list_users(struct sockaddr_in clientAddress, socklen_t addrLen){
	FILE *fp = fopen("users.txt", "r");
	if (fp == NULL) {
        printf("Error opening file\n");
        return;
    }
    
    char buffer[100];
	while (fgets(buffer, 100, fp)) {
		sendto(udpSocket, buffer, strlen(buffer), 0, (struct sockaddr*)&clientAddress, addrLen);
	}
	
	fclose(fp);
}

void create_topic(char *id, char * title, char * multicastAddress){
    for(int i = 0; i < 10; i++){
        if (strcmp(topicos[i].topic_id, "") == 0){
            strcpy(topicos[i].topic_id, id);
            strcpy(topicos[i].topic_tit, title);
            strcpy(topicos[i].topic_addr, multicastAddress);
            break;
        }
    }
}


int is_admin(char *buf, const char *filename, struct sockaddr_in clientAddress, socklen_t addrLen){
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
        printf("Error opening file\n");
        exit(1);
    	}

    	char buffer[100];
    	char *username;
    	char *password;
    	char *type;
    	char *user = strtok(buf, " ");
    	if (user == NULL) {
        	sendto(udpSocket, "please login first\n", strlen("please login first\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
        	fclose(fp);
        	return 0;
    	}
    	char *pass = strtok(NULL, " ");
    	if (pass == NULL) {
        	sendto(udpSocket, "please login first\n", strlen("please login first\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
        	fclose(fp);
        	return 0;
    	}

	while (fgets(buffer, 100, fp)) {
		username = strtok(buffer, ";");
		password = strtok(NULL, ";");
		type = strtok(NULL, "\n");
		
		if (strcmp(username, user) == 0 && strcmp(password, pass) == 0 && strcmp(type, "administrador") == 0){
			printf("admin logged in\n");
			sendto(udpSocket, "logged in\n", strlen("logged in\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
			fclose(fp);
			return 1;
		}
	}

	sendto(udpSocket, "this user doesnt have admin permissions\n", strlen("this user doesnt have admin permissions\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
	fclose(fp);
	return 0;
}

int client_login(char *buf, const char *filename, int socket){
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error opening file\n");
        exit(1);
        }

        char buffer[100];
        char *username;
        char *password;
        char *type;
        char *user = strtok(buf, " ");
        if (user == NULL) {
            write(socket, "please login first\n", strlen("please login first\n"));
            fclose(fp);
            return 0;
        }
        char *pass = strtok(NULL, " ");
        if (pass == NULL) {
            write(socket, "please login first\n", strlen("please login first\n"));
            fclose(fp);
            return 0;
        }

    while (fgets(buffer, 100, fp)) {
        username = strtok(buffer, ";");
        password = strtok(NULL, ";");
        type = strtok(NULL, "\n");
        
        if (strcmp(username, user) == 0 && strcmp(password, pass) == 0 && strcmp(type, "jornalista") == 0){
            printf("journalist logged in\n");
            write(socket, "logged in\n", strlen("logged in\n"));
            fclose(fp);
            return 1;
        }
        else if (strcmp(username, user) == 0 && strcmp(password, pass) == 0 && strcmp(type, "leitor") == 0){
            printf("reader logged in\n");
            write(socket, "logged in\n", strlen("logged in\n"));
            fclose(fp);
            return 2;
        }
    }

    write(socket, "invalid authentication\n", strlen("invalid authentication\n"));
    fclose(fp);
    return 0;
}

void* adminThread(void* arg) {
    struct sockaddr_in clientAddress = *((struct sockaddr_in*)arg);
    socklen_t addrLen = sizeof(clientAddress);
    char buffer[BUFLEN];
    while (1) {
    	if(end == 1) break;
      
        ssize_t recv_len = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&clientAddress, &addrLen);
        if (recv_len < 0) {
            perror("UDP receive error");
            exit(EXIT_FAILURE);
        }

		buffer[recv_len]='\0';
		buffer[strcspn(buffer, "\n")] = '\0';
		
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &clientAddress.sin_addr, ip, INET_ADDRSTRLEN);

		int flag = 0;
		pthread_mutex_lock(&ipsMutex);
		for (int i = 0; i < MAX_IPS; i++){
				if(strcmp(ip, ips[i]) == 0){
					flag = 1;
					break;
				}
		}
		pthread_mutex_unlock(&ipsMutex);
		if (flag == 0) {
    if (is_admin(buffer, file, clientAddress, addrLen) == 1) {
    pthread_mutex_lock(&ipsMutex);
    	if (num_ips < MAX_IPS) {
        for (int i = 0; i < MAX_IPS; i++) {
            if (strcmp(ips[i], "") == 0) {
                strcpy(ips[i], ip);
                num_ips++;
                break;
            }
        }
    } else {
        sendto(udpSocket, "max number of authentications reached\n", strlen("max number of authentications reached\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
    }
    pthread_mutex_unlock(&ipsMutex);
	}
    continue;
}
		char command[100];
		strncpy(command, strtok(buffer, " "), sizeof(command) - 1);
		command[sizeof(command) - 1] = '\0';

		if (strcmp(command, "ADD_USER") == 0) {
			char username[50], password[50], type[50];
        	char *token = strtok(NULL, " ");
        	
        	if (token != NULL) {
            	strcpy(username, token);
            	token = strtok(NULL, " ");
            	
        		if (token != NULL) {
            		strcpy(password, token);
            		token = strtok(NULL, " ");
            		
            		if (token != NULL) {
            		strcpy(type, token);
            			if (strcmp(type, "administrador") == 0 || strcmp(type, "leitor") == 0 || strcmp(type, "jornalista") == 0){
            			
            			token = strtok(NULL, " ");
            				if (token == NULL) {
            					pthread_mutex_lock(&adminMutex);
            					add_user(username, password, type, clientAddress, addrLen);
            					pthread_mutex_unlock(&adminMutex);
            					
            				}else printf("Couldn't Create (Wrong Input)\n");
            				
            			}else printf("Couldn't Create (Wrong Input)\n");
            			
        			}else printf("Couldn't Create (Wrong Input)\n");
        			
        		}else printf("Couldn't Create (Wrong Input)\n");
        		
        	}else printf("Couldn't Create (Wrong Input)\n");
        	
		} else if (strcmp(command, "DEL") == 0) {
			char username[50];
		    char *token = strtok(NULL, " ");
		    
        	if (token != NULL) {
            	strcpy(username, token);
            	token = strtok(NULL, " ");
            	
            	if (token == NULL) {
            		pthread_mutex_lock(&adminMutex);
            		remove_user(username, clientAddress, addrLen);
            		pthread_mutex_unlock(&adminMutex);
            		
            	}else printf("Couldn't Delete (Wrong Input)\n");
            	
            }else printf("Couldn't Delete (Wrong Input)\n");
            
		} else if (strcmp(command, "LIST") == 0) {
			char *token = strtok(NULL, " ");
			
        	if (token == NULL) {
        		pthread_mutex_lock(&adminMutex);
		    	list_users(clientAddress, addrLen);
		    	pthread_mutex_unlock(&adminMutex);
		    	
		    }else printf("Couldn't List (Wrong Input)\n");

		} else if (strcmp(command, "QUIT") == 0) {
			char *token = strtok(NULL, " ");

        	if (token == NULL) {
						char ip_rm[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &clientAddress.sin_addr, ip_rm, INET_ADDRSTRLEN);
						pthread_mutex_lock(&ipsMutex);
						for (int i = 0; i < MAX_IPS; i++){
							if (strcmp(ips[i], ip_rm) == 0){
								strcpy(ips[i], "");
								num_ips--;
								printf("admin logged out <%s>\n", ip_rm);
								sendto(udpSocket, "logged out\n", strlen("logged out\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
								break;
							}
						}
						pthread_mutex_unlock(&ipsMutex);

			}else printf("Couldn't Quit (Wrong Input)\n");

		} else if (strcmp(command, "QUIT_SERVER") == 0) {
			char *token = strtok(NULL, " ");

        	if (token == NULL) {
        		end = 1;
				kill(getpid(), SIGINT);
			}else printf("Couldn't Quit Server (Wrong Input)\n");

		}else sendto(udpSocket, "invalid command\n", strlen("invalid command\n"), 0, (struct sockaddr*)&clientAddress, addrLen);
    }
        }

void* clientThread(void* client_info) {
    struct ClientInfo* info = (struct ClientInfo*)client_info;
    int newSocket = info->socket;
    struct sockaddr_in clientAddr = info->address;
	char buffer[BUFLEN];
    int t;
    while (1) {
        if (end == 1)
            break;

        bzero(buffer, sizeof(buffer));
        ssize_t numBytes = read(newSocket, buffer, sizeof(buffer));
        if (numBytes < 0) {
            perror("TCP receive error");
            exit(EXIT_FAILURE);
        }
        buffer[numBytes] = '\0';
        
        if (strlen(buffer) == 0)
        			continue;
        char* trimmedBuffer = buffer;
        while (isspace(*trimmedBuffer))
            trimmedBuffer++;

        size_t length = strlen(trimmedBuffer);
        while (length > 0 && isspace(trimmedBuffer[length - 1]))
            trimmedBuffer[--length] = '\0';

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ip, INET_ADDRSTRLEN);
      
        int flag_client = 0;
        pthread_mutex_lock(&ipsMutex);
		for (int i = 0; i < MAX_IPS; i++){
			if(strcmp(ip, ips[i]) == 0){
				flag_client = 1;
				break;
			}
		}
		pthread_mutex_unlock(&ipsMutex);
		if (flag_client == 0) {
			t = client_login(buffer, file, newSocket);
			if (t == 1 || t == 2) {
    	if (num_ips < MAX_IPS) {
        for (int i = 0; i < MAX_IPS; i++) {
            if (strcmp(ips[i], "") == 0) {
                strcpy(ips[i], ip);
                num_ips++;
                break;
            }
        }
    } else {
        write(newSocket, "max number of authentications reached\n", strlen("max number of authentications reached\n"));
    }
    pthread_mutex_unlock(&ipsMutex);
	}
    continue;
    }
		
		if(t == 1){
			char command[100];
			strcpy(command, strtok(buffer, " "));

			if(strcmp(command, "CREATE_TOPIC") == 0){
				char *token = strtok(NULL, " ");
				char id[100], title[100];
				
        		if (token != NULL) {
        			strcpy(id, token);
        			token = strtok(NULL, " ");
            		
            		if (token != NULL) {
        				strcpy(title, token);
        				token = strtok(NULL, " ");
            		
            			if (token == NULL) {
            				char* multicastAddress = generateMulticastAddress(title);
            				pthread_mutex_lock(&clientMutex);
            				create_topic(id, title, multicastAddress);
            				pthread_mutex_unlock(&clientMutex);
            				write(newSocket, "OK\n", strlen("OK\n"));
            				
            			}else printf("Couldn't CREATE (Wrong Input)\n");
            		
            		}else printf("Couldn't CREATE (Wrong Input)\n");

        		}else printf("Couldn't CREATE (Wrong Input)\n");
        		
			}else if(strcmp(command, "SEND_NEWS") == 0){
				char *token = strtok(NULL, " ");
				char id[100], noticia[200];
				
        		if (token != NULL) {
        			strcpy(id, token);
        			token = strtok(NULL, " ");
            		
            		if (token != NULL) {
        				strcpy(noticia, token);
        				token = strtok(NULL, " ");
            		
            			if (token == NULL) {
            				for (int i = 0; i < 10; i++){
            					if(strcmp(topicos[i].topic_id, id) == 0){
            						sendMulticastMessage(topicos[i].topic_addr, noticia);
            						break;
            					}
            				}
            			}else printf("Couldn't SEND (Wrong Input)\n");
            		
            		}else printf("Couldn't SEND (Wrong Input)\n");

        		}else printf("Couldn't SEND (Wrong Input)\n");
        		
			}else if (strcmp(command, "QUIT") == 0){
				char *token = strtok(NULL, " ");

        		if (token == NULL) {
							char ip_rm[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(clientAddr.sin_addr), ip_rm, INET_ADDRSTRLEN);
							pthread_mutex_lock(&ipsMutex);
							for (int i = 0; i < MAX_IPS; i++){
								if (strcmp(ips[i], ip_rm) == 0){
									strcpy(ips[i], "");
									num_ips--;
									printf("journalist logged out <%s>\n", ip_rm);
									write(newSocket, "logged out\n", strlen("logged out\n"));
									break;
								}
							}
							pthread_mutex_unlock(&ipsMutex);
							break;
						}
			}else write(newSocket, "wrong command\n", strlen("wrong command\n"));
		}else if (t == 2){
			char command[100];
			strcpy(command, strtok(buffer, " "));
			
			if (strcmp(command, "LIST_TOPICS") == 0) {
				char *token = strtok(NULL, " ");
				
        		if (token == NULL) {
        			char lista[500];
        			lista[0] = '\0';
        			pthread_mutex_lock(&clientMutex);
					for(int i = 0; i < 10; i++){
        				if (strcmp(topicos[i].topic_tit, "") != 0){
        					strcat(lista, topicos[i].topic_id);
        					strcat(lista, ":");
        					strcat(lista, topicos[i].topic_tit);
        					strcat(lista, "\n");
        				}
    				}
    				write(newSocket, lista, strlen(lista));
    				pthread_mutex_unlock(&clientMutex);
    			}else printf("Couldn't LIST (Wrong Input)\n");
    			
			}else if(strcmp(command, "SUBSCRIBE_TOPIC") == 0){
				char *token = strtok(NULL, " ");
				char id[100];
        		if (token != NULL) {
        			strcpy(id, token);
        			token = strtok(NULL, " ");
            	
            		if (token == NULL) {
            			for (int i = 0; i < 10; i++){
            				if(strcmp(topicos[i].topic_id, id) == 0){
            					char multicastInfo[256];
            					snprintf(multicastInfo, sizeof(multicastInfo), "MULTICAST:%s", topicos[i].topic_addr);
            					write(newSocket, multicastInfo, strlen(multicastInfo));
            					break;
            				}
            			}
            		}else printf("Couldn't SUBSRCIBE (Wrong Input)\n");

        		}else printf("Couldn't SUBSCRIBE (Wrong Input)\n");

			}else if (strcmp(command, "QUIT") == 0){
				char *token = strtok(NULL, " ");

        		if (token == NULL) {
							char ip_rm[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &(clientAddr.sin_addr), ip_rm, INET_ADDRSTRLEN);
							pthread_mutex_lock(&ipsMutex);
							for (int i = 0; i < MAX_IPS; i++){
								if (strcmp(ips[i], ip_rm) == 0){
									strcpy(ips[i], "");
									num_ips--;
									printf("reader logged out <%s>\n", ip_rm);
									write(newSocket, "logged out\n", strlen("logged out\n"));
									break;
								}
							}
							pthread_mutex_unlock(&ipsMutex);
							break;
						}
			}else write(newSocket, "wrong command\n", strlen("wrong command\n"));
		}
	}
	close(newSocket);
    pthread_exit(NULL);
}

int main(int argc, char const *argv[]) {

	if (argc < 4) {
        printf("news_server {PORTO_NOTICIAS} {PORTO_CONFIG} {config file}\n");
        exit(-1);
    }
    pthread_mutex_init(&ipsMutex, NULL);
    pthread_mutex_init(&clientMutex, NULL);
    pthread_mutex_init(&adminMutex, NULL);
    signal(SIGINT, sigint_handler);

	file = argv[3];
		for (int i = 0; i < MAX_IPS; i++) strcpy(ips[i], "");
		
		for(int i = 0; i < 10; i++) topicos[i] = null_topico;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        perror("UDP socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    serverAddressUdp.sin_family = AF_INET;
    serverAddressUdp.sin_addr.s_addr = INADDR_ANY;
    serverAddressUdp.sin_port = htons(atoi(argv[2]));

    tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket == -1) {
        perror("TCP socket creation failed");
        exit(EXIT_FAILURE);
    }

    serverAddressTcp.sin_family = AF_INET;
    serverAddressTcp.sin_addr.s_addr = INADDR_ANY;
    serverAddressTcp.sin_port = htons(atoi(argv[1]));

    if (bind(udpSocket, (struct sockaddr *)&serverAddressUdp, sizeof(serverAddressUdp)) < 0) {
        perror("UDP socket bind failed");
        exit(EXIT_FAILURE);
    }

    if (bind(tcpSocket, (struct sockaddr *)&serverAddressTcp, sizeof(serverAddressTcp)) < 0) {
        perror("TCP socket bind failed");
        exit(EXIT_FAILURE);
    }


    if (listen(tcpSocket, 5) < 0) {
        perror("TCP socket listen failed");
        exit(EXIT_FAILURE);
    }
    
    while (1) {
    	if(end == 1) break;
    	fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(tcpSocket, &read_fds);
        FD_SET(udpSocket, &read_fds);
        
        if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }
        
        if (FD_ISSET(tcpSocket, &read_fds)) {
        	if(num_clients < MAX_CLIENTS){
        		socklen_t client_addr_len = sizeof(tcpClientAddress);
        		tcpClient = accept(tcpSocket, (struct sockaddr*)&tcpClientAddress, &client_addr_len);
        		if (tcpClient < 0) {
            		perror("Error accepting connection");
            		exit(EXIT_FAILURE);
        		}
        		
        		int* tcpClient_ptr = malloc(sizeof(int));
        		*tcpClient_ptr = tcpClient;
        		struct ClientInfo* clientInfo = malloc(sizeof(struct ClientInfo));
				clientInfo->socket = tcpClient;
				clientInfo->address = tcpClientAddress;
				if (pthread_create(&tcpThread[num_clients], NULL, clientThread, clientInfo) != 0) {
    				perror("Thread creation failed");
    				exit(EXIT_FAILURE);
				}
        		num_clients++;
        	}else{
        		printf("Maximum number of clients reached. Connection rejected.\n");
            	close(accept(tcpSocket, NULL, NULL));
        	}
        }
        if (FD_ISSET(udpSocket, &read_fds)) {
            struct sockaddr_in clientAddress;
        	socklen_t addrLen = sizeof(clientAddress);
        	 if (recvfrom(udpSocket, NULL, 0, MSG_PEEK, (struct sockaddr *)&clientAddress, &addrLen) == -1) {
            	perror("Failed to receive client address");
            	exit(EXIT_FAILURE);
        	}
	
        	if (pthread_create(&udpThread, NULL, adminThread, (void *)&clientAddress) != 0) {
            	perror("Thread creation failed");
            	exit(EXIT_FAILURE);
        	}

        	pthread_detach(udpThread);
    	}
    }
    
    clean_resources();
	return 0;
}
