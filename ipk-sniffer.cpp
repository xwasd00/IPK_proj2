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
#define TCP_PROTOCOL 6


void printPacket(char* payload, short plen){
	string buffer;


	for( short i = 0; i < plen; i++){
		if(i % 16 == 0){
			cout << "0x" << hex << i << ":";
		}
		if(i % 8 == 0){
			cout << " ";
		}
		printf("%02hhx ", payload[i]); 
		
		if(payload[i] > 32 && payload[i] < 126){

			buffer.append(&payload[i]);
		}
		else{
			buffer.append(".");
		}
		if(i % 16 == 15){
			cout << buffer.substr(i-15, 16) << endl;
		}
	}
	if(plen % 16 != 0){
		short offset = (plen/16)*16;
		//cout << dec << endl << endl << offset << "  " << plen << endl;
		for( int i = 0; i < (offset + 16 - plen); i++){
			cout  << "   ";
		}
		cout << buffer.substr(offset, plen - offset ) << endl;
	}
	cout << dec;

		

	/*
	for(short i = 0; i < line; i = i++){
		cout << "0x" << hex <<  i*16 << ":  ";
		for(short j = 0; j < 8; j++){
			pos = j+i*16;
			if(isprint(payload[pos])){
				buffer.append(payload[pos]);
			}
			else{
				buffer.append('.');
			}	
			cout << hex << int(payload[pos]) << " ";
		} 
		cout << " ";
		for(int j= 8; j < 16; j++){
			pos = j+i*16;
			if(isprint(payload[pos])){
				buffer.append(payload[pos]);
			}
			else{
				buffer.append('.');
			}	
			cout << hex << int(payload[pos]) << "  ";
		}

		cout << buffer.substr() << endl;
	}
	cout << buffer << endl;*/
}


void getInfo(tcphdr* tcp, u_short* src_port, u_short* dst_port, u_char** payload,short* plen){
		*src_port = tcp->th_sport<<8 | tcp->th_dport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
		*payload = (u_char*)(tcp + sizeof(tcphdr));
		*plen = *plen - sizeof(tcphdr);
		return;
}

void getInfo(udphdr* udp, u_short* src_port, u_short* dst_port, u_char** payload, short* plen){
		*src_port = udp->uh_sport<<8 | udp->uh_sport>>8;
		*dst_port = udp->uh_dport<<8 | udp->uh_dport>>8;
		*payload = (u_char*)(udp + sizeof(udphdr));
		*plen = *plen - sizeof(udphdr);
		return;
}



void printInfo(ip* iph, u_char** payload, short* plen){
	
	u_short src_port, dst_port;
	*plen = iph->ip_len<<8 | iph->ip_len>>8;
	*plen = *plen - iph->ip_hl*4;
	
	if(iph->ip_p == TCP_PROTOCOL){
		tcphdr* tcp = (tcphdr*)((const u_char*)iph + iph->ip_hl*4);
		getInfo( tcp, &src_port, &dst_port, payload, plen );
	}
	else{
		udphdr* udp = (udphdr*)((const u_char*)iph + iph->ip_hl*4);
		getInfo( udp, &src_port, &dst_port, payload, plen );
	}
	
	cout << inet_ntoa(iph->ip_src) << " : " << src_port << " > ";
	cout << inet_ntoa(iph->ip_dst) << " : " << dst_port << endl;
}

void printInfo(ip6_hdr* iph, u_char** payload, short* plen){
	
	u_short src_port, dst_port;
	*plen = iph->ip6_ctlun.ip6_un1.ip6_un1_plen<<8 | iph->ip6_ctlun.ip6_un1.ip6_un1_plen>>8;
	
	if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP_PROTOCOL){
		tcphdr* tcp = (tcphdr*)((const u_char*)iph + sizeof(ip6_hdr));
		getInfo( tcp, &src_port, &dst_port, payload, plen );
	}
	else{
		udphdr* udp = (udphdr*)((const u_char*)iph + sizeof(ip6_hdr));
		getInfo( udp, &src_port, &dst_port, payload, plen );
	}
	
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, (void*)&(iph->ip6_src), src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, (void*)&(iph->ip6_dst), dst, INET6_ADDRSTRLEN);
	cout << src << " : " << src_port << " > ";
	cout << dst << " : " << dst_port << endl;
}


void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
	u_char* payload = nullptr;
	short plen = 0;//TODO: plen a payload mazna neni treba

	struct tm * time;
	time = localtime(&(header->ts.tv_sec));
	cout << time->tm_hour << ":" << time->tm_min << ":" << time->tm_sec;
	cout << "." << header->ts.tv_usec << " ";


	ip* ip_header = (ip*)(packet + ETHERNET_SIZE);
	if (ip_header->ip_v == 4){
		printInfo(ip_header, &payload, &plen);
	}
	else {
		printInfo((ip6_hdr*)(ip_header), &payload, &plen);
	}


	if(payload == nullptr){
		cerr << "no data" << endl;
		return;
	}
	printPacket((char*)packet, header->caplen);
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
