
#ifndef _PS_SCAN_HPP_
#define _PS_SCAN_HPP_

// standard libraries
#include <signal.h>

// networking libraries
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>	// TCP header
#include <netinet/ip_icmp.h>	// ICMP header
#include <netinet/udp.h>	// UDP header
#include <netdb.h>	// for struct servent

#include "ps_netw.hpp"

// macros
#define TIMEOUT 4	// 4 seconds allowed for host to respond
#define SNAP_LEN 1518	// max number of bytes for every packet being sniffed
#define NO_PROMISC 0	// non promiscuous mode; do not sniff all traffic
#define READ_TIMEOUT 0	// timeout in milliseconds needed for certain platforms
#define SRC_PORT 2015	// set unoccupied, unofficial source port randomly

#define A_RECORD 1 	// DNS record type: A, for Address record
#define DNS_PORT 53	// DNS queries go to port# 53

#define MAX_RETRIES 3	// try sending packet at most 3 times

#define SIZE_ETHERNET 14	// size of ethernet headers is always exactly 14 bytes

/* 
 * pseudo header type used for checksum calculation instead of struct tcphdr alone
 * 	look in Scanner::getTCPpacket() for details about this header's fields
 */
struct pseudohdr {
	uint32_t src;
	uint32_t dst;
	unsigned char mbz;
	unsigned char protocol;
	uint16_t tcp_len;

	struct tcphdr hdrtcp;	// includes a tcp header too
};

struct dnshdr {
	uint16_t id;	// identification
	unsigned char qr:1;	// whether query (0) or response (1)
	unsigned char opcode:4;	// indicates the kind of query
	unsigned char aa:1;	// authoritative answer
	unsigned char tc:1;	// truncation flag
	unsigned char rd:1;	// whether recursion desired
	unsigned char ra:1;	// whether recursive query support is available
	unsigned char z:1;	// reserved
	unsigned char rcode:4;	// response code set as part of responses

	uint16_t qdcount;	// specifies number of entries in the question section
	uint16_t ancount;	// specifies number of resource records in the answer section
	uint16_t nscount;	// specifies number of nameserver resource records in authority records section
	uint16_t arcount;	// specifies number of resource records in the additional records section
};

/** stucture for dns question part that follows dns header **/
struct dnsquery {	// question name or domain name part is added separately to packet
	uint16_t qtype;	// type of the query e.g. A record, MX record, etc.
	uint16_t qclass;	// class of the query
};

// global variable for packet capture session
extern pcap_t *snifferSession;	// handle to packet capture session

// global declaration of functions
void sigTimeout(int);	// signal handler function
void recvdPacket(u_char *, const struct pcap_pkthdr *, const u_char *);

class Scanner {
	private:
		char machineIP[INET_ADDRSTRLEN];	// local machine's IP address
	public:
		void initPktSniffing();
		void runJobs();
		void getMachineIPaddr(char *);
		char * getTCPpacket(char *, int, char *, char *, int);
		uint16_t calcChecksum( uint16_t *, int);
		char * getDNSQueryPacket( unsigned char *, int, int &);
		char * getRandomUDPpayload();
		void printScanResults();
		char * getServiceName(char *, int);
		void getServiceVersion(int, char *, service_version_t &);
		void printServiceVersions(service_version_t &);
};


#endif