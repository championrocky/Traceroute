#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netdb.h> // for struct addrinfo and the function getaddrinfo()
#include <string.h> 
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <errno.h>



#define BUFSIZE 1500

void proc_v4(char *, ssize_t, struct timeval *);
void send_v4(void);
pid_t pid;
int nsent;
int datalen = 56;
int sockfd;
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];
struct timeval sendtime;
int flag=0;
char *host;

struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME; 
	hints.ai_family = family; 
	hints.ai_socktype = socktype; 

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return (NULL);

	return (res); /* return pointer to first on linked list*/
}


char * sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128];		

	switch (sa->sa_family) {
	case AF_INET: 
	{
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}
	default:
		return(NULL);
	}
    return (NULL);
}

struct proto
{
	void (*fproc) (char *, ssize_t, struct timeval *);
	void (*fsend) (void);									////pointer to a function
	struct sockaddr *sasend; // sockaddr{} for send, from getaddrinfo
	struct sockaddr *sarecv; // sockaddr{} for receiving;
	socklen_t salen;
	int icmpproto;
} *pr;										////pointer to a structure

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) 
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	
	out->tv_sec -= in->tv_sec;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short	*w = addr;
	unsigned short	answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{  
    
	int hlen1, icmplen;
	double rtt;
	struct ip *ip;           
	struct icmp *icmp;			
	struct timeval *tvsend;

	ip = (struct ip *) ptr; /* start of IP header */
	hlen1 = ip->ip_hl << 2; /* length of IP header */ 

	icmp = (struct icmp *)(ptr + hlen1); /* start of ICMP header */

	if ( (icmplen = len - hlen1) < 8)				
	{
		printf("icmplen (%d) < 8", icmplen);		
		exit(0);
	}

	if (icmp->icmp_type == ICMP_ECHOREPLY) 			
    {
		if (icmp->icmp_id != pid)					
			return; /* not a response to our ECHO REQUEST */
		if (icmplen < 16)							
		{
			printf("icmplen (%d) < 16", icmplen);
            printf("\n");
			exit(0);

		}

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec/1000.0;
        printf(" %.3f ms %d bytes packet  ",rtt, icmplen);
        flag=1;

    }
	else   
	{
        printf(" %d bytes packet  ",icmplen);
	}
    
}

void send_v4(void)  
{
        int len;
        struct icmp *icmp;

        icmp = (struct icmp *) sendbuf;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = pid;
        icmp->icmp_seq = nsent++;
     
        gettimeofday(&sendtime,NULL);
        gettimeofday((struct timeval *) icmp->icmp_data, NULL);

        len = 8 + datalen; /* checksum ICMP header and data */
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = in_cksum((u_short *) icmp, len); 
        
        sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen); //sending ICMP packet
    
}

void sig_alrm(int signo)
{
	(*pr->fsend)(); 
	
	alarm(1);
}

void readloop(void)
{
	int size;
	char recvbuf[BUFSIZE];
	socklen_t len;
	ssize_t n;
	int ttl=1;
	struct timeval tval;
    sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);	//socket descriptor
	//setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));			//setting TTL value for 1st time
    sig_alrm(SIGALRM); /* send first packet */

    do
    {   
		setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));		//TTL keeps increasing as we move closer to destination
        len = pr->salen;
        n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
        if (n < 0) 
                    {
                        if (errno == EINTR)          ///EINTR is already defined
                            continue;
                        else
                        {
                            printf("recvfrom error\n");
                            exit(0);
                        }
                    }
                    gettimeofday(&tval, NULL); 
					printf(" %d %s ",ttl, sock_ntop_host(pr->sarecv, pr-> salen));	//destination's or router's IP addres
                    (*pr->fproc) (recvbuf, n, &tval); //recvbuf is the packet received
        if(flag==1)
        {
            break;
        }
		ttl++;
		 printf("\n");
	}while(ttl<=30);
}

int main(int argc, char *argv[])
{
	struct addrinfo *ai;

	host = argv[1];

	pid = getpid();

	signal(SIGALRM, sig_alrm);

	ai = host_serv(host, NULL, 0, 0);
	printf("traceroute %s %s 30 hops max \n", ai->ai_canonname, sock_ntop_host(ai->ai_addr, ai->ai_addrlen));
	if(ai->ai_family == AF_INET)
		pr = &proto_v4;					
	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;
    
	readloop();
    printf("\n");
	return 0;
}
