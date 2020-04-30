#include <iostream>
#include <pcap.h>
#include "Args.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <bitset>

using namespace std;

#define ETHERNET_SIZE 14
#define IPv4_MIN_SIZE 20
#define TCP_PROTOCOL 6

void tcpGetInfo(tcphdr* tcp, u_short* src_port, u_short* dst_port, u_char* payload){
		*src_port = tcp->th_sport<<8 | tcp->th_dport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
		payload = (u_char*)(tcp + tcp->th_off * 4);
		cout << endl << tcp->th_ack << endl;
		return;
}

void udpGetInfo(udphdr* udp, u_short* src_port, u_short* dst_port, u_char* payload){
		*src_port = udp->uh_sport<<8 | udp->uh_sport>>8;
		*dst_port = udp->uh_dport<<8 | udp->uh_dport>>8;
		payload = (u_char*)(udp + sizeof(udphdr));
		return;
}

void ipv4Header(ip* ip_header){
	if ( ip_header->ip_hl * 4 < IPv4_MIN_SIZE){
		cerr << "ipv4 wrong header" <<endl;
		return;
	}
	u_short src_port, dst_port;
	u_char* payload;
	if(ip_header->ip_p == TCP_PROTOCOL){
		tcphdr* tcp = (tcphdr*)((const u_char*)ip_header + ip_header->ip_hl * 4);
		tcpGetInfo( tcp, &src_port, &dst_port, payload );
	}
	else{
		udphdr* udp = (udphdr*)((const u_char*)ip_header + ip_header->ip_hl * 4);
		udpGetInfo( udp, &src_port, &dst_port, payload );
	}
	//cout << "src_a: " << ip_header->ip_src.s_addr << " , dst_a: " << ip_header->ip_dst.s_addr << endl;
	cout << "src_p: " << src_port << " , dst_p: " << dst_port << endl;


}

void ipv6Header(ip6_hdr* ip_header){
	cout << "ipv6" << endl;
}


void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
	cout << header->ts.tv_sec;

	ip* ip_header = (ip*)(packet + ETHERNET_SIZE);
	if (ip_header->ip_v != 4){
		ip6_hdr* ip6_header = (ip6_hdr*)(ip_header);
		ipv6Header(ip6_header);
	}
	else {
		ipv4Header(ip_header);
	}
	
	cout << "packet: " << packet << endl;
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
