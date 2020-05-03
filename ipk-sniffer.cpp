#include <iostream>
#include <pcap.h>
#include "Args.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <iomanip>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define ETHERNET_SIZE 14
#define TCP_PROTOCOL 6
#define CACHE_SIZE 10
#define CACHE_BUFF 2048

char cache[CACHE_SIZE][CACHE_BUFF] = {0, 0, 0, 0, 0};
short off[CACHE_SIZE];
stringstream ss[CACHE_SIZE];
short ptr = 0;



void printPacket(char* payload, short len, short offset){
	char buffer[17] = {0};
	short start = offset % 16;
	short space = offset % 8;
	short end_hex = (start + 15) % 16;

	for( short i = offset; i < len; i++){
		if(i % 16 == start){
			printf("0x%04x: ", i);
		}
		if(i % 8 == space){
			cout << " ";
		}
		
		printf("%02hhx ", payload[i]); 
		
		if( payload[i] > 31 && payload[i] < 126){
			buffer[(i - start) % 16] = payload[i];
		}
		else{
			buffer[(i - start) % 16] = '.';
		}
		if(i % 16 == end_hex){
			cout << "  " << buffer << endl;
			memset(&buffer, 0, sizeof(buffer));
		}
	}
	if(len % 16 != start){
		short fill = 16 - (len-offset)%16;
		for( int i = 0; i < fill; i++){
			cout  << "   ";
		}
		cout << "  " <<  buffer << endl;
	}
	return;
}


void getInfo(tcphdr* tcp, u_short* src_port, u_short* dst_port, short* offset){
		*src_port = tcp->th_sport<<8 | tcp->th_sport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
		*offset = *offset + sizeof(tcphdr);
		return;
}

void getInfo(udphdr* udp, u_short* src_port, u_short* dst_port, short* offset){
		*src_port = udp->uh_sport<<8 | udp->uh_sport>>8;
		*dst_port = udp->uh_dport<<8 | udp->uh_dport>>8;
		*offset = *offset + sizeof(udphdr);
		return;
}


void getAddress(ip* iph, char* src_addr, char* dst_addr, bool* tcp, short* offset){
	
	if(iph->ip_p == TCP_PROTOCOL){
		*tcp = true;
	}
	else{
		*tcp = false;
	}
	
	sockaddr_in sa;
	char serv[NI_MAXSERV];
	sa.sin_family = AF_INET;
	sa.sin_addr = iph->ip_src;
	getnameinfo((const sockaddr*) &sa, sizeof(struct sockaddr_in), src_addr, NI_MAXHOST, 
														serv, NI_MAXSERV, 0);
	sa.sin_addr = iph->ip_dst;
	getnameinfo((const sockaddr*) &sa, sizeof(struct sockaddr_in), dst_addr, NI_MAXHOST, 
														serv, NI_MAXSERV, 0);

	/*
	strcpy(src_addr, inet_ntoa(iph->ip_src));
	strcpy(dst_addr, inet_ntoa(iph->ip_dst));
	*/
	*offset = *offset + iph->ip_hl * 4;
}

void getAddress(ip6_hdr* iph, char* src_addr, char* dst_addr, bool* tcp, short* offset){
	
	if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP_PROTOCOL){
		*tcp = true;
	}
	else{
		*tcp = false;
	}
	
	char serv[NI_MAXSERV];
	sockaddr_in6 sa;
	sa.sin6_family = AF_INET6;
	sa.sin6_addr = iph->ip6_src;
	getnameinfo((const sockaddr*) &sa, sizeof(struct sockaddr_in6), src_addr, NI_MAXHOST, serv, NI_MAXSERV, 0);
	sa.sin6_addr = iph->ip6_dst;
	getnameinfo((const sockaddr*) &sa, sizeof(struct sockaddr_in6), dst_addr, NI_MAXHOST, serv, NI_MAXSERV, 0);


	
/*
	inet_ntop(AF_INET6, (void*)&(iph->ip6_src), src_addr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, (void*)&(iph->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
*/	
	*offset = *offset + sizeof(ip6_hdr);
}


void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
	
	tm* time;
	time = localtime(&(header->ts.tv_sec));	
	
	for(int i = 0; i < CACHE_SIZE; i++){
		if(strcmp(cache[i], (char*) packet) == 0){
			printf("%02d:%02d:%02d.%d ", time->tm_hour, time->tm_min, time->tm_sec, (int)header->ts.tv_usec);
			cout << ss[i].str();
			printPacket((char*)packet, off[i], 0);
			cout << endl;
			printPacket((char*)packet, header->caplen, off[i]);
			cout << endl;
			return;
		}
	}

	bool tcp = false;
	u_short src_port, dst_port;
	short offset = ETHERNET_SIZE;
	/*
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];
	*/
	char src_addr[NI_MAXHOST];
	char dst_addr[NI_MAXHOST];

	ip* iph = (ip*)(packet + offset);
	if (iph->ip_v == 4){
		getAddress(iph, src_addr, dst_addr, &tcp, &offset);
	}
	else {
		getAddress((ip6_hdr*)(iph), src_addr, dst_addr, &tcp, &offset);
	}

	if(tcp){
		tcphdr* tcp = (tcphdr*)(packet + offset);
		getInfo(tcp, &src_port, &dst_port, &offset);
	}
	else{
		udphdr* udp = (udphdr*)(packet + offset);
		getInfo(udp, &src_port, &dst_port, &offset);
	}
	printf("%02d:%02d:%02d.%d ", time->tm_hour, time->tm_min, time->tm_sec, (int)header->ts.tv_usec);
	
	if(header->caplen < CACHE_BUFF){
		strcpy(cache[ptr], (char *)packet);
		off[ptr] = offset;
		ss[ptr] << src_addr << " : " << src_port << " > " << dst_addr << " : " << dst_port << endl << endl;
		ptr = (ptr+1)%CACHE_SIZE;
	}
	cout << src_addr << " : " << src_port << " > " << dst_addr << " : " << dst_port << endl << endl;

	printPacket((char*)packet, offset, 0);
	cout << endl;
	printPacket((char*)packet, header->caplen, offset);
	cout << endl;
	/*printPacket((char*)packet, offset);
	cout << endl;
	printPacket((char*)(packet + offset), header->caplen - offset);
	cout << endl;*/
	return;
}

int main(int argc, char** argv){
	pcap_t *handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 ip;

	Args arg;
	int retval = arg.getOpts(argc, argv); 
	switch(retval){
		case 0:
			break;
		case -1:
			return 0;
			break;
		default:
			return retval;
			break;
	}

	handle = pcap_open_live(arg.dev.data(), BUFSIZ, 0, 1000, errbuff);
	if (handle == NULL) {
		cerr << "Couldn't open device " << errbuff << endl;
		return 1;
	}
	
	
	if (pcap_lookupnet(arg.dev.data(), &ip, &mask, errbuff) == -1) {
		cerr << "Couldn't get netmask for device " << errbuff << endl;
		ip = 0;
		mask = 0;
	}
	if (pcap_compile(handle, &fp, arg.filter.data(), 0, ip) == -1) {
		cerr << "Couldn't parse filter " << pcap_geterr(handle) << endl;
		return 1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		cerr << "Couldn't install filter" << pcap_geterr(handle) << endl;
		return 1;
	}
	

	if (pcap_loop(handle, arg.num, callback, nullptr) != 0){
		cerr << "pcap_loop error : " << pcap_geterr(handle) << endl;
        return 1;
	}
}
