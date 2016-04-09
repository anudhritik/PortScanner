
#include "ps_scan.hpp"
#include "ps_netw.hpp"
#include "ps_lib.hpp"

// standard libraries
#include <iomanip>

// networking libraries
#include <netinet/ip.h>	// ip header
#include <netinet/udp.h>	// udp header
#include <ifaddrs.h>
#include <sys/socket.h>

// recall all global variables
pcap_t *snifferSession;

void Scanner::initPktSniffing() {

	/** set up a default network device to capture packets **/
	char errbuf[PCAP_ERRBUF_SIZE];	// to fill error message
	char *netwdev = pcap_lookupdev(errbuf);	// returns a default network device
	if (netwdev == NULL) {
		fprintf(stderr, "\nError: Unable to find a default network device.\n");
		exit(1);
	}

	/** fetch IPv4 network number & netmask for network device **/
	bpf_u_int32 netwnum, netmask;
	if ( pcap_lookupnet(netwdev, &netwnum, &netmask, errbuf) == -1 ) {
		fprintf(stderr, "\nWarning: Unable to IP address and netmask for device.\n");
		netwnum = 0;	// unreachable IP
		netmask = 0;	// no netmask
	}

	/** open network device to sniff packets; get a handle to the capture **/
	snifferSession = pcap_open_live( netwdev, SNAP_LEN, NO_PROMISC, READ_TIMEOUT, errbuf);
	if (snifferSession == NULL) {
		fprintf(stderr, "\nError: Unable to open network device.\n");
		exit(1);
	}

	/** setup a filter for sniffing selected traffic **/
	char filter_exp[40];
	snprintf(filter_exp, sizeof filter_exp, "dst port %d or ip proto \\icmp", SRC_PORT);

	/** need to setup a packet filter program with filter expression **/
	struct bpf_program fp;
	if (pcap_compile(snifferSession, &fp, filter_exp, 0, netmask) == -1) {
		fprintf( stderr, "\nError: Unable to setup packet filter program, error message: %s\n ", pcap_geterr(snifferSession) );
		exit(1);
	}

	/** finally, set the packet filter **/
	if ( pcap_setfilter(snifferSession, &fp) == -1) {
		fprintf( stderr, "\nError: Unable to setup packet filter, error message: %s\n ", pcap_geterr(snifferSession) );
		exit(1);
	}

	pcap_freecode(&fp);	// free BPF program

}

void Scanner::runJobs() {

	// cout << endl;	// new line
	
	char *packet = NULL;	// packet to be sent to dst port
	int packetLen;	// length of packet

	// get source machine's IP address
	getMachineIPaddr(this->machineIP);

	int sockfd;	// socket handle, set according to type of scan

	while ( !workQueue.empty() ) {	// until all jobs are done
		
		job_t job = workQueue.front();	// get next job

		/** make sockaddr_in structure from destination IP address in job **/
		struct sockaddr_in sin;
		sin.sin_family = AF_INET;
		inet_pton( AF_INET, job.ipAddr, &sin.sin_addr);	// copy destination IP address
		sin.sin_port = htons(job.portNo);	// copy destination port number

		if ( strcasecmp(job.scanType, "UDP") != 0 ) {	// for all scan types other than "UDP"; strcasecmp() used instead of std::string::compare for case insensitivity

			/** make a packet with appropriate TCP flags set **/
			packet = getTCPpacket( job.ipAddr, job.portNo, job.scanType, machineIP, SRC_PORT );

			/** get length of packet for TCP scans **/
			struct iphdr *ipheader = (struct iphdr *) packet;	// reference to ip header in packet
			packetLen = ipheader->tot_len;

			/** keep a Raw socket handy for TCP scans **/
			if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 ) {
				fprintf(stderr, "\nError: Unable to create raw socket.\n");
				exit(1);
			}
		
		} else if ( (strcasecmp(job.scanType, "UDP") == 0) && job.portNo == DNS_PORT ) {	// for a DNS query

			/** make a DNS query packet **/
			packet = getDNSQueryPacket( (unsigned char *) "www.stackoverflow.com", 	// domain name for DNS query
										A_RECORD, 	// Address record type DNS query
										packetLen 	// to get length of packet
										);

			/** keep a UDP socket handy for dns queries **/
			if ( (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				fprintf(stderr, "\nError: Unable to create UDP socket for DNS queries.\n");
				exit(1);
			}

		} else {	// all other standard "UDP" scan types other than DNS query type

			/** send a fixed-length random payload **/
			packet = getRandomUDPpayload();

			/** do not forget the UDP socket handle **/
			if ( (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				fprintf(stderr, "\nError: Unable to create UDP socket.\n");
				exit(1);
			}

			/** packet length **/
			packetLen = 20;	// for fixed-lenth (20 bytes)

		}

		/** because a custom IP header was written in packets, set a socket option to include custom ip header **/
		if ( strcasecmp(job.scanType, "UDP") != 0 ) {	// not UDP scan type
			int optval = 1;
			const int *valptr = &optval;

			if ( setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, valptr, sizeof(optval)) < 0 ) {	// set socket option
				fprintf(stderr, "\nWarning: Unable to set HDRINCL option for IP: %s port: %d", job.ipAddr, job.portNo);
			}
		}

		/** setup an alarm buzzer to check status of response from destination **/
		struct sigaction act;
		act.sa_handler = sigTimeout;	// alarm signal handler function
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGALRM, &act, 0);	// register alarm signal

		/** get set to send packet over to destination **/
		int retry = 0;
		while (retry < MAX_RETRIES) {

			/** send packet **/
			if ( sendto(sockfd, packet, packetLen, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0 ) {
				fprintf(stderr, "\nError: Unable to send packet for IP: %s port: %d", job.ipAddr, job.portNo);
				exit(1);
			}

			/** wait for response from destination but timeout after 4 seconds if no response **/
			alarm(TIMEOUT);	// allow 4 seconds max for response

			/** when response packet arrives from destination within timeout window, process 1 packet **/
			int dispStatus = pcap_dispatch(snifferSession, 1, recvdPacket, (u_char *) &job);
			alarm(0);	// cancel buzzing alarm if 1 packet received

			if (dispStatus == -2 || dispStatus == -1) {	// if call to pcap_breakloop() was done due to timeout OR some error occured
				retry++;	// try once more
				continue;
			} else {
				break;	// count was exhausted, we have our 1 packet parsed
			}

		}

		workQueue.pop();	// move on to next job

	}

	// free used resources once jobs are done
	close(sockfd);
	pcap_close(snifferSession);

}

void Scanner::getMachineIPaddr(char *hostip) {

	memset(hostip, 0x00, INET_ADDRSTRLEN);	// zero-out ip addr holder initially

	struct ifaddrs *addrStruct = NULL;	// store linked list of network interfaces of local system
	struct ifaddrs *ifa = NULL;	// to iterate over interface linked list

	getifaddrs(&addrStruct);	// creates linked list

	for (ifa = addrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if ( ifa->ifa_addr->sa_family == AF_INET ) {	// concerned with IPv4 address

        	if ( strcmp(ifa->ifa_name, "eth0") == 0 ) {	// for network interface type: ethernet
        		struct in_addr addr = ( (struct sockaddr_in *) ifa->ifa_addr )->sin_addr;
        		snprintf( hostip, INET_ADDRSTRLEN, "%s", inet_ntoa(addr) );
        	}
        }
    }

    if ( addrStruct != NULL ) {
    	freeifaddrs(addrStruct);	// free interface addresses
    }

    if ( strlen(hostip) == 0 ) {	// if IP not populated
    	fprintf(stderr, "\nError: Could not determine local machine's IP.\n");
    	exit(1);
    }

}

char * Scanner::getTCPpacket(char *dstIP, int dstPort, char *scanname, char *srcIP, int srcPort) {

	/** refer IP, TCP headers **/
	struct iphdr *ipHeader = NULL;
	struct tcphdr *tcpHeader = NULL;

	static char datagram[4096];	// buffer representing packet
	memset(datagram, 0x00, sizeof datagram);	// zero-out buffer initially

	/** consruct IP header part of packet **/
	ipHeader = (struct iphdr *) datagram;
	ipHeader->ihl = 5;	// internet header length; number of 32-bit words in header
	ipHeader->version = 4;	// IPv4
	ipHeader->tos = 0;	// type of service; 0 as standard, some other service like VoIP may require setting this field
	ipHeader->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);	// total length of ip header; (struct ip) guarantees IP header without options
	ipHeader->id = htons(9876);	// set some simple identification
	ipHeader->frag_off = 0;	// no fragmentation
	ipHeader->ttl = 64;	// seconds, can also be seen as hop counts (decrements by 1); standard seen as 64 usually (e.g. ping program)
	ipHeader->protocol = IPPROTO_TCP;	// value 6 for TCP protocol
	ipHeader->check = 0;	// set to 0 before checksum calculation
	ipHeader->saddr = inet_addr(srcIP);	// source address as an integer (32-bit)
	ipHeader->daddr = inet_addr(dstIP);	// destination address as an integer (32-bit)

	ipHeader->check = calcChecksum( (uint16_t *) datagram, sizeof(struct ip) );	// calculate actual checksum for ip header; pass ptr ipHeader if you need to

	/** consruct TCP header part of packet **/
	tcpHeader = (struct tcphdr *) ( datagram + sizeof(struct ip) );
	tcpHeader->source = htons(srcPort);	// source port
	tcpHeader->dest = htons(dstPort);	// destination port
	tcpHeader->seq = htonl(100000);	// sequence number; for identification of packet
	tcpHeader->ack_seq = 0;	// acknowledgment number
	tcpHeader->doff = (sizeof(struct tcphdr) / 4);	// specifies size of tcphdr in 32-bit words
	tcpHeader->fin = 0;	// set all flags to 0 prior to sending packet
	tcpHeader->syn = 0;
	tcpHeader->rst = 0;
	tcpHeader->psh = 0;
	tcpHeader->ack = 0;
	tcpHeader->urg = 0;
	tcpHeader->window = htons(14600);	// size of receive window; max 65535 bytes; optimal usually: bandwidth * latency (bytes)
	tcpHeader->check = 0;	// set to 0 before checksum calculation
	tcpHeader->urg_ptr = 0;	// urgent pointer

	/** set tcp header flags according to scan type on record **/
	const char *allscans[6] = { "SYN", "NULL", "FIN", "XMAS", "ACK", "UDP" };
	int i;

	for (i = 0; i < 6; i++) {	// like assigning integer to each scan type
		if ( strcasecmp(scanname, allscans[i]) == 0 ) {	// ignore case when comparing strings
			break;
		}
	}

	switch (i) {
		case 0:	// SYN scan
			tcpHeader->syn = 1;
			break;
		case 1:	// NULL scan
			break;	// no flags to set
		case 2:	// FIN scan
			tcpHeader->fin = 1;
			break;
		case 3:	// XMAS scan
			tcpHeader->fin = 1;
			tcpHeader->psh = 1;
			tcpHeader->urg = 1;
			break;
		case 4:	// ACK scan
			tcpHeader->ack = 1;
			break;
		default:	// scan type cannot be "UDP" here
			break;
	}

	/** TCP header checksum needs to be calculated along with a pseudo header **/
	struct pseudohdr soodohdr;
	soodohdr.src = inet_addr(srcIP);	// integer form of source IP address
	soodohdr.dst = inet_addr(dstIP);	// integer form of destination IP address
	soodohdr.mbz = 0;	// 8 reserved bits, all set to 0
	soodohdr.protocol = IPPROTO_TCP;	// TCP protocol
	soodohdr.tcp_len = htons( sizeof(struct tcphdr) );
	memcpy( &soodohdr.hdrtcp, tcpHeader, sizeof(struct tcphdr) );	// tcp header field of pseudo header

	/** calculate tcp header checksum now that we have our pseudo header **/
	tcpHeader->check = calcChecksum( (uint16_t *) &soodohdr, sizeof(struct pseudohdr) );

	return datagram;	// serve packet
	
}

uint16_t Scanner::calcChecksum( uint16_t *pktref, int hdrlen) {
	
	uint32_t sum = 0;	// store final sum here; 0 initially; let this be 32-bit for carry over bits

	for (int i = 0; i < (hdrlen / 2); i++) {	// e.g. header length 20 / 2 = 10 16-bit portions to iterate
		sum += *pktref;	// keep adding current 16-bit header portion to last sum
		pktref++;	// increment to next 16-bit portion
	}

	/** just in case header length turned out odd **/
	if ( (hdrlen % 2) != 0 ) {
		pktref++;
		sum += *pktref;	// add the one-odd 16-bit header portion
	}

	/** add carry over bits to last sum **/
	sum = (sum & 0xffff) 	// only last 16-bits in checksum
					+ (sum >> 16);	// only carry over bits
	sum = sum + (sum >> 16);	// in case there was still that one last carry over bit

	return ((uint16_t) ~sum);	// 16-bit one's complement of 'sum'

}

char * Scanner::getDNSQueryPacket( unsigned char *domainName, int recordType, int &pktLength) {
	
	static char dnsbuf[4096];	// dns datagram buffer
	memset(dnsbuf, 0x00, sizeof dnsbuf);	// zero-out buffer initially

	/** make dns header in packet **/
	struct dnshdr *dnsHeader = (struct dnshdr *) dnsbuf;	// get reference to dns header
	dnsHeader->id = htons(123);	// set identification number
	dnsHeader->qr = 0;	// is a query
	dnsHeader->opcode = 0;	// set 0 for a standard query
	dnsHeader->aa = 0;	// non-authoritative answer
	dnsHeader->tc = 0;	// no truncation
	dnsHeader->rd = 1;	// recursively query for answer
	dnsHeader->ra = 0;	// recursive query support not available
	dnsHeader->z = 0;
	dnsHeader->rcode = 0;	// response code not set
	dnsHeader->qdcount = 1;	// 1 question
	dnsHeader->ancount = 0;	// no answers
	dnsHeader->nscount = 0;	// no nameservers
	dnsHeader->arcount = 0;	// no additional records

	/** make dns question portion in packet **/
	unsigned char *qname = (unsigned char *) ( dnsbuf + sizeof(struct dnshdr) );	// get reference to location after dns header to append domain name details
	sprintf( (char *) qname, "%s", domainName);	// fill domain name to mark start of dns question portion of packet
	struct dnsquery *dnsQ = (struct dnsquery *) ( dnsbuf + sizeof(struct dnshdr) + (strlen( (const char *) qname ) + 1) );	// reference to location after dns header and question name
	dnsQ->qtype = htons(recordType);	// query type A
	dnsQ->qclass = htons(1);	// represents Internet address

	/** get length of entire DNS query packet **/
	pktLength = sizeof(struct dnshdr) + strlen( (const char *) qname ) + 1 + sizeof(struct dnsquery);

	return dnsbuf;	// serve packet

}

char * Scanner::getRandomUDPpayload() {

	static char payload[20];	// randomly set to 20 bytes; 512 bytes is considered a good bet but too large

	for (int i = 0; i < 20; i++) {
		payload[i] = 'x';
	}

	return payload;
}

/*
 * once response timeout window expires, sigTimeout() ensures that no 
 * attempt shall be made to process packets.
 */
void sigTimeout(int signum) {
	(void) signum;	// to suppress " unused parameter 'signum' " warning
	cout << "." << std::flush;
	pcap_breakloop(snifferSession);	// break out
}

void recvdPacket(u_char *args, const struct pcap_pkthdr *pheader, const u_char *packet) {
	
	job_t *job = (job_t *) args;	// get reference to job
	scan_result_t scanrslt;	// reference to scan results type structure

	snprintf(scanrslt.ipAddr, INET_ADDRSTRLEN, "%s", job->ipAddr);	// fill in IP addr for scan
	scanrslt.portNo = job->portNo;	// fill in port number for scan
	snprintf(scanrslt.scanType, 5, "%s", job->scanType);	// fill in type of scan

	if (pheader == NULL) {
		fprintf(stderr, "\nError: Packet timestamp unusually not set in received packet.\n");
		return;	// something's not right, terminate
	}

	/** parse received packet to make useful deductions **/

	struct iphdr *ipHeader = (struct iphdr *) (packet + SIZE_ETHERNET);	// reference to ip header in packet
	
	/** check IP header length **/
	int iphLen = (ipHeader->ihl) * 4;
	if (iphLen < 20) {	// minimum size of IP header
		fprintf(stderr, "\nError: Invalid IP header length of %d found in received packet.\n", iphLen);
		return;	// terminate packet parsing
	}

	int tcphLen;	// to store tcp header length

	struct icmphdr *icmpHeader = NULL;	// ICMP header type
	struct tcphdr *tcpHeader = NULL;	// TCP header type
	struct udphdr *udpHeader = NULL;	// UDP header type

	/** arrive at appropriate conclusions based on IP header's protocol portion in packet **/
	switch (ipHeader->protocol) {
		case 1:	// ICMP protocol; control messages that give out useful conclusions about port statuses
			icmpHeader = (struct icmphdr *) (packet + SIZE_ETHERNET + iphLen);

			/** now check type of control message **/
			if (icmpHeader->type == 3) {	// type: Destination Unreachable; check 'code' to get more info
				switch (icmpHeader->code) {
					case 1: case 2: case 9:
					case 10: case 13:	// implies port is "Filtered"
						snprintf(scanrslt.portState, 15, "Filtered");
						break;
					case 3:	// port unreachable
						if ( strcasecmp(job->scanType, "UDP") == 0) {	// if scan type: UDP
							snprintf(scanrslt.portState, 15, "Closed");
						} else {	// for scan types: TCP
							snprintf(scanrslt.portState, 15, "Open|Filtered");
						}
						break;
					default:
						break;
				}
			}
			break;
		case 6:	// TCP protocol; 
			tcpHeader = (struct tcphdr *) (packet + SIZE_ETHERNET + iphLen);	// get reference to TCP header from packet
			tcphLen = tcpHeader->doff * 4;

			if (tcphLen < 20) {	// minimum size of TCP header
				fprintf(stderr, "\nError: Invalid TCP header length of %d found in received packet.\n", tcphLen);
				return;	// terminate packet parsing
			}

			/** SYN port scanning **/
			if ( (tcpHeader->syn == 1) && (tcpHeader->ack == 1) ) {
				snprintf(scanrslt.portState, 15, "Open");
			} else if ( tcpHeader->rst == 1 ) {
				if ( strcasecmp(job->scanType, "ACK") == 0 ) {	// if scan type: ACK
					snprintf(scanrslt.portState, 15, "Unfiltered");
				} else {
					snprintf(scanrslt.portState, 15, "Closed");
				}
			}

			break;
		case 17:	// UDP protocol
			udpHeader = (struct udphdr *) (packet + SIZE_ETHERNET + iphLen);	// get reference to UDP header from packet

			/** check if packet originated from destination port in current 'job' **/
			if(ntohs(udpHeader->source) == job->portNo) {
				snprintf(scanrslt.portState, 15, "Open");
			}
			break;
		default:
			break;
	}

	scansResultsVect.push_back(scanrslt);

}

void Scanner::printScanResults() {
	
	cout << "\n\n";	// new line

	set<string>::iterator ipSetStrItr;
	set<string>::iterator scansSetStrItr;
	set<int>::iterator portSetItr;
	vector<scan_result_t>::iterator scanRsltsVectItr;

	int portbuf;

	for ( ipSetStrItr = ips_set.begin(); ipSetStrItr != ips_set.end(); ipSetStrItr++ ) {	// for every dst IP address on record
		cout << setfill('-') << setw(100) << "\n";
		cout << "IP Address: " << *ipSetStrItr << endl;
		cout << setfill('-') << setw(100) << "\n";

		for ( scanRsltsVectItr = scansResultsVect.begin(); scanRsltsVectItr != scansResultsVect.end(); scanRsltsVectItr++ ) {
			if ( strcmp( (*scanRsltsVectItr).ipAddr, (*ipSetStrItr).c_str() ) == 0 ) {	// filter by IP address
				cout << setiosflags(ios::left) << setfill(' ') << setw(10) << (*scanRsltsVectItr).portNo 
							<< setw(25) << getServiceName( (*scanRsltsVectItr).scanType, (*scanRsltsVectItr).portNo );
				cout << (*scanRsltsVectItr).scanType << " (" << (*scanRsltsVectItr).portState << ") ";
			}
			cout << endl;
		}

		cout << setfill('-') << setw(70) << "\n";
		cout << "\nService Version Detection for IP Address: " << *ipSetStrItr << "\n";
		cout << setfill('-') << setw(70) << "\n";
		cout << "\nPort" << "\t" << "Service Version" << endl;
		cout << setfill('-') << setw(70) << "\n";

		for ( portSetItr = ports_set.begin(); portSetItr != ports_set.end(); portSetItr++ ) {	// for every port of a dst IP address
			portbuf = *portSetItr;

			if ( (portbuf == 22) || (portbuf == 24) || (portbuf == 43) || (portbuf == 80) || (portbuf == 110) || (portbuf == 143) ) {
				service_version_t srcVers;
				getServiceVersion(portbuf, const_cast<char *>((*ipSetStrItr).c_str()), srcVers);
				printServiceVersions(srcVers);
			}
		}
	}
}

/*
 * function returns name of standard service running on port number passed as argument
 */
char * Scanner::getServiceName(char *scanname, int port) {
	
	static char buf[100];

	/** get name of service running on destination port **/
	struct servent *service;
	if (strcasecmp(scanname, "UDP") != 0) {	// for TCP scans
		service = getservbyport(htons(port), "TCP");
	} else {	// for UDP scans
		service = getservbyport(htons(port), "UDP");
	}

	if (service != NULL) {	// a standard known service was found
		snprintf(buf, 100, "%s", service->s_name);
	} else {	// couldn't figure out service name
		snprintf(buf, 100, "Unassigned");
	}

	return buf;

}

void Scanner::getServiceVersion(int dstport, char *dstip, service_version_t &svern) {

	/** create a local TCP socket to connect to dst IP address **/
	int sockfd;	// socket handle
	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "\nError: Unable to create a TCP client while querying for services versions.");
		return;
	}

	/** fill in details of the dst address socket structure **/
	struct sockaddr_in dstAddr;
	dstAddr.sin_family = AF_INET;
	dstAddr.sin_port = htons(dstport);

	struct hostent *hostinfo;
	if ( (hostinfo = gethostbyname(dstip)) == NULL ) {
		fprintf(stderr, "\nError: Could not resolve dest IP address while querying for services versions.");
		return;
	}

	memcpy( (char *) &dstAddr.sin_addr.s_addr, (char *) hostinfo->h_addr, hostinfo->h_length );

	/** initiate socket connection to dest IP address **/
	if ( connect( sockfd, (struct sockaddr *) &dstAddr, sizeof(dstAddr) ) < 0 ) {
		fprintf(stderr, "\nError: Could not establish connect to destination IP address: %s Port: %d while querying for services versions.", dstip, dstport);
		return;
	}

	/** get set to query ports on destination IP address **/
	char recvbuffer[200];
	int retval;	// receive status from dest IP address
	int i, buflen;
	char *serv = NULL;
	char *str = NULL;

	char dataString[] = "hello world!";	// query text to be sent to destination IP
	int bytestoSend = strlen(dataString);
	int bytesSent = 0, totalBytesSent = 0;

	char delim[] = " ";
	char *token = NULL;

	switch(dstport) {
		case 22:	// SSH, index 0 in svern.sercversion
			if ( (retval = recv(sockfd, recvbuffer, 200, 0)) <= 0 ) {
				fprintf(stderr, "\nError: Unable to read response for services detection from dest IP address.");
				return;
			}

			buflen = strlen( (char *) recvbuffer);
			for (i = 0; i < buflen; i++) {
				if (recvbuffer[i] == '\n')
					break;
				svern.sercversion[0][i] = recvbuffer[i];
			}
			svern.sercversion[0][i] = '\0';	// null terminator

			break;
		case 24:	// SMTP, index 1 in svern->sercversion
			if ((retval = recv(sockfd, recvbuffer, 200, 0)) <= 0 ) {
				fprintf(stderr, "\nError: Unable to read response for services detection from dest IP address.");
				return;
			}

			// copy recvbuffer into a temp str
			str = (char *) malloc(strlen(recvbuffer) + 1);
			snprintf(str, strlen(recvbuffer), "%s", recvbuffer);

			i = 0;
			for (token = strtok(str, delim); ((i < 6) && token); i++, token = strtok(NULL, delim) ) {
				switch(i) {
					case 2:	// service versions separated by a " "
						strcpy(svern.sercversion[1], token);
						strcat(svern.sercversion[1], " ");
						break;
					case 3:
						strcat(svern.sercversion[1], token);
						strcat(svern.sercversion[1], " ");
						break;
					case 4:
						strcat(svern.sercversion[1], token);
						strcat(svern.sercversion[1], " ");
						break;
					case 5:
						strcat(svern.sercversion[1], token);
						break;
					default:
						break;
				}
			}
			free(str);

			break;
		case 43:	// WHOIS protocol to be used to send query and received response
					// WHOIS, index 2 in svern->sercversion
			/** send text query over to dst **/
			while ( bytestoSend > 0 ) {	// data present
				if ( (bytesSent = write(sockfd, dataString, bytestoSend)) < 0 ) {
					fprintf(stderr, "\nError: Unable to send query text for services detection to dest IP address.");
					return;		
				} else {
					bytestoSend -= bytesSent;
					totalBytesSent += bytesSent;
				}
			}

			if ( (retval = recv(sockfd, recvbuffer, 200, 0)) <= 0 ) {	// receive response in buffer
				fprintf(stderr, "\nError: Unable to read response for services detection from dest IP address.");
				return;
			}

			if ( (serv = strstr(recvbuffer, "Server Version")) == NULL ) {
				snprintf(svern.sercversion[2], 80, "Unknown service.");
			} else {

				/** fill in service version from what appears after "Server Version" upto end of line **/
				serv += strlen("Server Version") + 1;
				int addtnlen = strlen(serv);
				for (i = 0; i < addtnlen; i++) {
					if (serv[i] == '\n') {
						break;
					}
					svern.sercversion[2][i] = serv[i];
				}
				svern.sercversion[2][i] = '\0';	// null termination
			}
			break;
		case 80:	// HTTP, index 3 in svern->sercversion

			break;
		case 110:	// POP, index 4 in svern->sercversion
			if ( (retval = recv(sockfd, recvbuffer, 200, 0)) <= 0 ) {
				fprintf(stderr, "\nError: Unable to read response for services detection from dest IP address.");
				return;
			}
			// copy recvbuffer into a temp str
			str = (char *) malloc(strlen(recvbuffer) + 1);
			snprintf(str, strlen(recvbuffer), "%s", recvbuffer);

			snprintf(svern.sercversion[4], strlen("Version: "), "Version: ");	// version to print		

			i = 0;
			for (token = strtok(str, delim); ((i < 3) && token); i++, token = strtok(NULL, delim) ) {
				switch(i) {
					case 1:	// service versions separated by a " "
						strcpy(svern.sercversion[4], token);
						break;
					default:
						break;
				}
			}

			free(str);
			break;
		case 143:	// IMAP, index 5 in svern->sercversion
			if ( (retval = recv(sockfd, recvbuffer, 200, 0)) <= 0 ) {
				fprintf(stderr, "\nError: Unable to read response for services detection from dest IP address.");
				return;
			}

			// copy recvbuffer into a temp str
			str = NULL;
			snprintf(str, strlen(recvbuffer), "%s", recvbuffer);

			snprintf(svern.sercversion[5], strlen("Version: "), "Version: ");	// version to print		

			i = 0;
			for (token = strtok(str, delim); ((i < 4) && token); i++, token = strtok(NULL, delim) ) {
				switch(i) {
					case 3:	// service versions separated by a " "
						strcat(svern.sercversion[5], token);
						break;
					default:
						break;
				}
			}

			break;
		default:
			break;
	}

}


void Scanner::printServiceVersions(service_version_t &svc) {
	
	cout << endl;

	int i;
	for (i = 0; i < 6; i++)	{
		switch(i) {
			case 0:	// SSH
				cout << "22" << "\t" << svc.sercversion[i] << "\n";
				break;
			case 1:	// SMTP
				cout << "24" << "\t" << svc.sercversion[i] << "\n";
				break;
			case 2:	// WHOIS
				cout << "43" << "\t" << svc.sercversion[i] << "\n";
				break;
			case 3:	// HTTP
				cout << "80" << "\t" << svc.sercversion[i] << "\n";
				break;
			case 4:	// POP
				cout << "110" << "\t" << svc.sercversion[i] << "\n";
				break;
			case 5:	// IMAP
				cout << "143" << "\t" << svc.sercversion[i] << "\n";
				break;
			default:
				break;
		}
	}
}