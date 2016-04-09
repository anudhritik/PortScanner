
/*
 * References:
 * 	http://linux.die.net/man/
 * 	http://stackoverflow.com/
 * 	http://en.wikipedia.org/
 * 	http://www.tcpdump.org/pcap.htm	// sniff packets
 * 	http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm	// TCP header, TCP checksum calc
 * 	http://www.binarytides.com	// Raw UDP sockets; DNS query
 * 	http://sock-raw.org/papers/syn_scanner	// SYN port scanner
 * 	http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf 	// dns protocol
 * 	http://montcs.bloomu.edu/Information/LowLevel/linux-socket-programming.html	// raw socket programming
 * 	http://www.manpagez.com/ 	// libpcap
 */

#include "ps_lib.hpp"

// standard libraries
#include <iostream>
#include <cstdio>
#include <limits.h>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <set>

/** recall all global variables **/
set<int> ports_set;
set<string> ips_set;
// set<string> reservedIPs_set;
set<string> scans_set;

const char *scans[6] = { "SYN", "NULL", "FIN", "XMAS", "ACK", "UDP" };	// list of all scan types

// int resv_IPcheck = 0;	// indicates whether or not IP address is checked with reserved IPs list on record

/* default constructor for class ArgsParser */
ArgsParser::ArgsParser() {
	memset(this->filename, 0x00, sizeof(this->filename));	// null filename by default
	this->num_threads = 0;	// 0 by default to indicate no-multi-threading	
}

/*
 * usage() -> void
 * displays instructions on how to run the program
 */
void ArgsParser::usage(FILE *file) {
 	if (file == NULL)
 		file = stdout;	// set standard output as file stream by default

 	fprintf(file, "./portScanner [OPTIONS] \n"
 					"	--help						\tPrint instructions on how to run portScanner\n"
 					"	--ports <ports to scan>				\tScan specified ports on IP address Eg. $ ./portScanner --ports 1,10,90-100\n"
 					"	--ip <IP address to scan>			\tScan ports on specified IP address. Eg. $ ./portScanner --ip 129.79.247.87\n"
 					"	--prefix <IP prefix to scan>			\tScan a range of IP addresses. Eg. $ ./portScanner --prefix 127.0.0.1/24\n"
 					"	--file <file name containing IP addresses to scan>\tRead specified file name that contains list of IP addresses to scan.\n"
 					"								Eg. $ ./portScanner --file ipaddresses.txt\n"
 					"	--speedup <parallel threads to use>		\tMulti-threaded version of portScanner; specifies number of threads to be used. \n"
 					"								Rounds down floating point numbers. Eg. $ ./portScanner --speedup 5\n"
 					"	--scan <one or more scans>			\tType of scan to be performed. Known scan types are SYN, NULL, FIN, XMAS, ACK, UDP.\n"
 					"								Eg. $ ./portScanner --scan SYN XMAS FIN\n"
			);
}

/*
 * parse_args() -> void
 * makes sense of each command line argument specified beside the program
 */
void ArgsParser::parse_args(int argc, char *argv[]) {
 	
	/* all long options that can be specified with ./portScanner */
 	struct option longopts[]  = {
		{"help", 	no_argument, 		0, 	'h'},
		{"ports", 	required_argument, 	0, 	'p'},
		{"ip", 		required_argument, 	0, 	'i'},
		{"prefix", 	required_argument, 	0, 	'x'},
		{"file", 	required_argument, 	0, 	'f'},
		{"speedup", required_argument, 	0, 	't'},
		{"scan", 	required_argument, 	0, 	's'},
		{0, 0, 0, 0}
	};

 	int g;	// to grab return value of getopt_long()
 	int longindex = 0;	// array index of struct longopts set by getopt_long()
 	while ( (g = getopt_long(argc, argv, "", longopts, &longindex)) != -1 ) {
 		switch(g) {
			case 'h':
				this->usage(stdout);
				exit(0);
			case 'p':
				this->getports(optarg);
				break;
			case 'i':
				this->getIP(optarg);
				break;
			case 'x':
				this->parse_prefixes(optarg, ips_set);
				break;
			case 'f':
				this->readIPfile(optarg);
				break;
			case 't':
				this->num_threads = atoi(optarg);
				if (num_threads <= 0) {
					fprintf(stderr, "Error: Invalid number of threads specified.\n");
					this->usage(stderr);
					exit(1);
				}
				break;
			case 's':
				this->parse_scans(argc, argv);
				break;
			default:
				this->usage(stderr);
				exit(1);
		}
 	}

 	if ( ips_set.empty() ) {	// case where user did not specify any IP addresss at all
 		fprintf(stderr, "Error: At least one IP address needed to scan on.\n");
 		this->usage(stderr);
 		exit(1);
 	}

 	if ( ports_set.empty() ) {	// if no ports were entered i.e. "--ports " was not a cli argument, use default ports 1-1024
 		for (int i = 1; i <= 1024; i++ ) {
 			ports_set.insert(i);
 		}
 	}

 	if ( scans_set.empty() ) {	// similarly, if no scan types were specified at cli, then add all scan types to the kitty
 		for (int i = 0; i < 6; i++) {
 			scans_set.insert(scans[i]);
 		}
 	}
}

/*// make a list of all reserved IP addresses that user cannot use to port scan
void ArgsParser::fill_resv_IPs() {

	resv_IPcheck = 1;	// set flag to indicate reserved IP address is to follow

	// following set of reserved IP prefixes is as per the wiki link
	char *resv[16] = { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", 
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", 
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", 
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32" };

	for (int i = 0; i < 16; i++) {
		parse_prefixes(const_char<char *>(resv[i]), reservedIPs_vect);	// fill each reserved IP range into reserved IPs list
	}

}*/

/*
 * getports() -> void
 * makes note of each port specified at command line
 */
void ArgsParser::getports(char *str) {
	char delim[] = ",";	// tokenize char array on ","
	char *token;	// token holder

	// make a copy of original string argument
	char str_cpy[strlen(str) + 1];
	snprintf(str_cpy, (strlen(str) + 1), "%s", str);

	for ( (token = strtok(str_cpy, delim)); token; token = strtok(NULL, delim) ) {	// tokenize until all tokens are retrieved
		string token_str(token);	// convert to type: string
		size_t dash_pos;	// holds index of the "-" if it is present in a token
		if ( ( dash_pos = token_str.find("-") ) != string::npos ) {	// check if "-" is present in token
			
			string port1_str(token_str.substr(0, dash_pos));	// string containing number upto "-"
			
			if (port1_str.empty()) {	// case when a negative port number was specified; REJECT such negative port numbers
				fprintf(stderr, "Error: Negative port numbers are invalid. Port numbers from 1 up to 65535 are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			int start_port = atoi(port1_str.c_str());	// convert to integer

			if (start_port == 0) {
				fprintf(stderr, "Error: Port# 0 not allowed. Port numbers from 1 up to 65535 are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			if (start_port > 65535) {
				fprintf(stderr, "Error: Ports greater than 65535 are invalid. Port numbers from 1 up to 65535 only are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			string port2_str(token_str.substr(dash_pos + 1));	// string containing number following the "-"

			int p;
			if ( ( p = atoi(port2_str.c_str()) ) < 0 ) {	// case where second port in range is negative
				fprintf(stderr, "Error: Negative port numbers are invalid. Port numbers from 1 up to 65535 are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			int end_port = atoi(port2_str.c_str());

			if (end_port > 65535) {
				fprintf(stderr, "Error: Ports greater than 65535 are invalid. Port numbers from 1 up to 65535 only are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			if (start_port > end_port) {	// e.g. "--ports 23-0,47"
				fprintf(stderr, "Error: Invalid range of ports.\n");
				this->usage(stderr);
				exit(1);
			}

			for (int i = start_port; i <= end_port; i++)	// fill ports vector with all ports from the start to end of the ports range
				ports_set.insert(i);
			
		} else {
			int p;
			if ( (p = atoi(token)) == 0 || p > 65535 ) {
				fprintf(stderr, "Error: Unacceptable port number specified. Port numbers from 1 up to 65535 only are valid.\n");
				this->usage(stderr);
				exit(1);
			}

			ports_set.insert(atoi(token));
		}
	}
}

/* parses IP address specified with "--ip" option, checks its validity */
void ArgsParser::getIP(char *ip) {
	struct hostent *hostinfo;	// hostent struct contains information like IP address, host name, etc.

	this->checkIP(ip);	// first, check if valid IP address

	if ( (hostinfo = gethostbyname(ip)) == NULL) {	// this check takes care of invalid input like negative IP addr octets too, weird characters in octets, among others
		fprintf(stderr, "Error: Something's not right with the IP addresses.\n");
		this->usage(stderr);
		exit(1);
	}

	struct sockaddr_in hostip;	// to store IP address data structure
	hostip.sin_family = AF_INET;	// set Internet Addressing as IP family type
	memcpy( (char *) &hostip.sin_addr.s_addr, (char *) hostinfo->h_addr, hostinfo->h_length );	// register IP address of host specified at cli
	
	string ip_holder(inet_ntoa(hostip.sin_addr));	// convert IP char array to string

	ips_set.insert(ip_holder);	// add to IP kitty

}

/* checks if
 ** IPv4 address is in valid format (xxx.xxx.xxx.xxx)
 ** IP address is not an IETF and IANA-specified reserved IP addresses as stated at
 *** 	http://en.wikipedia.org/wiki/Reserved_IP_addresses
 */
void ArgsParser::checkIP(char *ip) {

	if (strcmp(ip, "localhost") == 0) {	// "localhost" needs to be considered as a valid reference to IP 127.0.0.1
		return;
	}

	// now check for valid ip address format first e.g. ignore ip address: "18" or "12.172", etc.
	char *token;
	char delim[] = ".";
	int count;

	// copy IP to keep it safely untouched
	char ip_cpy[strlen(ip) + 1];
	snprintf(ip_cpy, sizeof ip_cpy, "%s", ip);

	for ( count = 0, token = strtok(ip_cpy, delim); (count < 4 && token != NULL); (token = strtok(NULL, delim)), count++ ) {
		continue;
	}

	if (count != 4) {	// all cases other than (count = 4) imply invalid IP address format
		fprintf(stderr, "Error: Invalid IP address format. Good IP example: 129.79.247.1\n");
		this->usage(stderr);
		exit(1);
	} 

/*	// once IP format OK, check IP with reserved IPs list
	if ( ( strvect_itr = find(reservedIPs_vect.begin(), reservedIPs_vect.end(), (string) ip_cpy) ) != reservedIPs_vect.end()) {	// IP found in reserved IPs list
		fprintf(stderr, "Error: A known reserved IP address is not allowed.\n"
			"More details on reserved IPs: http://en.wikipedia.org/wiki/Reserved_IP_addresses\n");
		usage(stderr);
		exit(1);
	}	// else all OK*/

}

/*
 * parses an IP prefix string in format "xxx.xxx.xxx.xxx/xx" (networkID/prefix)
 * takes a set container as argument to unique record all IPs in range into the container
 */
void ArgsParser::parse_prefixes(char *prefix, set<string> &setvar) {
	
	// copy "prefix" into a new variable; keep "prefix" untouched coz strtok() misbehaves
	char prefix_cpy[strlen(prefix) + 1];
	snprintf(prefix_cpy, sizeof prefix_cpy, "%s", prefix);

	char *token;	// to tokenize IP prefix by separating forward-slash
	char delim[] = "/";
	char *netw_addr = new char[INET_ADDRSTRLEN + 1];	// allocate memory to hold IP
	char *lead_bits = new char[3];	// number after "/" in IP prefix cannot be more than 2 digits + 1 for null-terminator
	int i = 0;

	/* separate IP from trailing bits part */
	for ( (token = strtok(prefix_cpy, delim)); (token != NULL && i < 2); (token = strtok(NULL, delim)), i++ ) {
		switch(i) {
			case 0:
				snprintf(netw_addr, (strlen(token) + 1), "%s", token);
				break;
			case 1:
				snprintf(lead_bits, (strlen(token) + 1), "%s", token);
				break;
			default:
				break;
		}
	}

	if (i != 2) {	// all cases other than "i = 2" should mean an error; terminate program
		fprintf(stderr, "Error: Something's not right with the IP prefix.\n");
		this->usage(stderr);
		exit(1);
	}

	/*// if this is reserved IP addresses prefix parsing, bypass the IP check
	if (resv_IPcheck != 1) {
		this->checkIP(netw_addr);
	}*/

	this->checkIP(netw_addr);	// validate IP

	unsigned long uint_addr;	// to store network byte order long of string IP (long -> 4 bytes)
	if ( (i = inet_aton(netw_addr, (struct in_addr *) &uint_addr)) < 1 ) {	// convert IP to long in network byte order
		fprintf(stderr, "Error: Could not understand network address in IP prefix.\n");	// inet_aton() returns non-zero for SUCCESS
		this->usage(stderr);
		exit(1);
	}
	
	uint32_t rev_endn = this->convert_endianness( (uint32_t) uint_addr);	// reverse endianness

	// create netmask
	uint32_t netw_bits = atoi(lead_bits);	// convert string to integer
	int host_bits = (32 - netw_bits);	// 32-bit IPv4 address would have host_bits amount reserved to get host addresses
	uint32_t netmask = UINT_MAX << host_bits;	// UINT_MAX to pacify ISO C90 warning when using "4294967295"

	uint32_t masked_rev_endn = rev_endn & netmask;	// apply Netmask
	uint32_t revofmaskedrev_endn = this->convert_endianness(masked_rev_endn);	// reverse endianness again before using inet_ntoa() coz it will reverse it anyway
	
	// store netmasked reverse endianned IP as string
	char next_ip[20];
	memset(next_ip, 0x00, sizeof next_ip);	// zero-out IP holder initially
	sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &revofmaskedrev_endn ) );

	setvar.insert( (string) next_ip );	// push first IP in range to IP kitty

	/* push all successively generated IP addresses in specified range to vector */
	uint32_t loopvar = 1;
	uint32_t orred;
	uint32_t revorred;
	while ( loopvar < (uint32_t) this->powerof2(host_bits) ) {	// loop until all end of IP range where all host bits are set

		orred = masked_rev_endn | loopvar;	// generate next binary
		revorred = convert_endianness(orred);	// reverse endianness before inet_ntoa()
		memset(next_ip, 0x00, sizeof next_ip);	// flush buffer
		sprintf( next_ip, "%s", inet_ntoa( *(struct in_addr *) &revorred ) );
		setvar.insert( (string) next_ip );	// add to IP kitty

		loopvar++;
	}

	/* free allocated memory */
	delete[] netw_addr;
	delete[] lead_bits;

}

/* converts endianness of a number (specifically from little-endian to big-endian for x86 machines) */
inline uint32_t ArgsParser::convert_endianness(uint32_t n) {
	return ( (n << 24) | ( (n << 8) & 0xff0000 ) | ( (n >> 8) & 0xff00 ) | (n >> 24) );
}

/* returns 2 raised to (number passed as argument) */
inline uint32_t ArgsParser::powerof2(int n) {
	return ( pow(2.0, (double) n) );	// math function for a raised to b: pow(a, b)
}

/* reads and stores the set of IPs/IP prefixes contained in a text file */
void ArgsParser::readIPfile(char *file) {
	ifstream fin;	// input file stream
	fin.open(file);	// open file
	string lof;	// to grab each line from file
	size_t slashpos;	// to grab position of "/" in IP if any

	if (fin.is_open()) {	// checks if input stream is well associated with file
		while (fin.good()) {	// no errors encountered with file stream so far
			getline(fin, lof);
			if ( strcmp(lof.c_str(), "") == 0) {
				continue;
			} else if ( (slashpos = lof.find("/")) != string::npos) {	// check if there's an IP prefix in file
				this->parse_prefixes(const_cast<char *>(lof.c_str()), ips_set);	// remove constness using const_cast<type>
			} else {	// just IP not an IP prefix
				this->getIP( const_cast<char *>( lof.c_str() ) );
			}
		}
	} else {
		fprintf(stderr, "Could not open target file: \"%s\"\n", file);
		this->usage(stderr);
		exit(1);
	}


	fin.close();	// close file finally
}

/*
 * parses the type/s of scans specified by user at command line after "--scan"
 * scan types are case-insensitive
 */
void ArgsParser::parse_scans(int argc, char *argv[]) {

	int i;
	for (i = 1; i < argc; i++) {	// look for "--scan" string in each cli argument except the first
		if (strcmp(argv[i], "--scan") == 0) {
			break;
		}
	}

	/* go through "scan types" entries following "--scan " but only until 
	 * either the end of all arguments is reached or another program option is found, 
	 * e.g. "--scan XMAS FIN"
	 * e.g. "--scan SYN NULL --speedup 10"
	 */
	 while ( ((i + 1) < argc) && (*argv[i + 1] != '-') ) {

	 	int j;
	 	for (j = 0; j < 6; j++) {	// check with each known scan type
	 		if ( strcasecmp(argv[i + 1], scans[j]) != 0 )	// ignore case when comparing
	 			continue;
	 		else {
	 			scans_set.insert(argv[i + 1]);	// if scan type match found, make note of that scan type
	 			break;
	 		}
	 	}

	 	if (j == 6) {	// specified scan type unknown, throw Error
	 		fprintf(stderr, "Error: Unknown scan type specified.\n");
	 		this->usage(stderr);
	 		scans_set.clear();	// ignore "--scan " input completely
			exit(1);
	 	}

	 	i++;

	 }

}

/* prints all elements found in vector<int> container passed as argument */
void ArgsParser::print_setelems(set<int> &setvar) {
	set<int>::iterator intset_itr;	// to go through set containing ints
	for ( intset_itr = setvar.begin(); intset_itr != setvar.end(); intset_itr++)
		cout << *intset_itr << endl;
}

/* overloaded print_vectelems() function for vector<string> */
void ArgsParser::print_setelems(set<string> &setvar) {
	set<string>::iterator strset_itr;	// to go through set containing strings
	for ( strset_itr = setvar.begin(); strset_itr != setvar.end(); strset_itr++)
		cout << *strset_itr << endl;
}

int ArgsParser::get_threads() {
	return this->num_threads;
}