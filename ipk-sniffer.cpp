/*************************************************/
/************* Síťový analyzátor *****************/
/********** projekt do předmětu IPK **************/
/*********** Michal Sova (xsovam00) **************/
/*************************************************/

#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <arpa/inet.h>
#include "Args.h"

using namespace std;

#define ETHERNET_SIZE 14
#define TCP_PROTOCOL 6


/**
 * @brief funkce pro vypsání paketu
 * @param payload ukazatel na začátek paketu
 * @param len velikost paketu, velikost vypisované části
 * @param offset v případě, že hlavička je již vypsaná, velikost hlavičky
 */
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

/**
 * @brief funkce, která uloží do src_port a dst_port zdrojový a cílový port z protokolu a nastaví offset
 * @param tcp ukazatel na začátek tcp hlavičky
 * @param src_port zdrojový port
 * @param dst_port cílový port
 * @param offset offset od původního začátku paketu
 */
void getInfo(tcphdr* tcp, u_short* src_port, u_short* dst_port, short* offset){
		*src_port = tcp->th_sport<<8 | tcp->th_sport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
		*offset = *offset + sizeof(tcphdr);
		return;
}
/**
 * @brief funkce, která uloží do src_port a dst_port zdrojový a cílový port z protokolu a nastaví offset
 * @param udp ukazatel na začátek udp hlavičky
 * @param src_port zdrojový port
 * @param dst_port cílový port
 * @param offset offset od původního začátku paketu
 */
void getInfo(udphdr* udp, u_short* src_port, u_short* dst_port, short* offset){
		*src_port = udp->uh_sport<<8 | udp->uh_sport>>8;
		*dst_port = udp->uh_dport<<8 | udp->uh_dport>>8;
		*offset = *offset + sizeof(udphdr);
		return;
}


/**
 * @brief funkce, která získá uloží do src_addr a dst_addr zdrojovou a cílovou adresu
 * @param iph ip hlavička
 * @param src_addr zdrojová adresa
 * @param dst_addr cílová adresa
 * @param tcp true => jde o tcp protokol, false => jde o udp protokol
 * @param offset offset od původního začátku paketu
 */
void getAddress(ip* iph, char* src_addr, char* dst_addr, bool* tcp, short* offset){

	// protokol:
	if(iph->ip_p == TCP_PROTOCOL){
		*tcp = true;
	}
	else{
		*tcp = false;
	}

	// posunutí offsetu:
	*offset = *offset + iph->ip_hl * 4;
	
	// získání adres:
	inet_ntop(AF_INET, (void*)&(iph->ip_src), src_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)&(iph->ip_dst), dst_addr, INET_ADDRSTRLEN);
	return;
}

/**
 * @brief funkce, která získá uloží do src_addr a dst_addr zdrojovou a cílovou adresu
 * @param iph ip hlavička
 * @param src_addr zdrojová adresa
 * @param dst_addr cílová adresa
 * @param tcp true => jde o tcp protokol, false => jde o udp protokol
 * @param offset offset od původního začátku paketu
 */
void getAddress(ip6_hdr* iph, char* src_addr, char* dst_addr, bool* tcp, short* offset){
	
	// protokol:
	if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP_PROTOCOL){
		*tcp = true;
	}
	else{
		*tcp = false;
	}

	// posunutí offsetu:
	*offset = *offset + sizeof(ip6_hdr);
	
	// získání adres:
	inet_ntop(AF_INET6, (void*)&(iph->ip6_src), src_addr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, (void*)&(iph->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
	return;
}

/**
 * @brief funkce k výpisu informací o paketu
 * @param user -
 * @param header hlavička obsahující informace o paketu (například čas)
 * @param packet ukazatel na začátek paketu
 * */
void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
	
	// struktura, pomocí níž se lehce vypíše čas
	tm* time;
	time = localtime(&(header->ts.tv_sec));	
	
	// jde o tcp nebo udp protokol
	bool tcp = false;

	// port zdroje a cíle
	u_short src_port, dst_port;

	// offset, na další hlavičku
	// ze začátku nastaven na velikost ethernetové hlavičky
	short offset = ETHERNET_SIZE;

	// adresa zdroje a cíle
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];

	ip* iph = (ip*)(packet + offset);
	// jde o IPv4 hlavičku
	if (iph->ip_v == 4){
		// získání adres + typu protokolu (tcp/udp) + posunutí offsetu o velikost halvičky
		getAddress(iph, src_addr, dst_addr, &tcp, &offset);
	}
	// jde o IPv6
	else {
		// získání adres + typu protokolu (tcp/udp) + posunutí offsetu o velikost hlavičky
		getAddress((ip6_hdr*)(iph), src_addr, dst_addr, &tcp, &offset);
	}

	// jde o TCP protokol
	if(tcp){
		// získání portů + posunutí offsetu o velikost tcp protokolu
		tcphdr* tcp = (tcphdr*)(packet + offset);
		getInfo(tcp, &src_port, &dst_port, &offset);
	}
	// jde o UDP protokol
	else{
		// získání portů + posunutí offsetu o velikost tcp protokolu
		udphdr* udp = (udphdr*)(packet + offset);
		getInfo(udp, &src_port, &dst_port, &offset);
	}

	// vypsání času, adres a portů
	printf("%02d:%02d:%02d.%d ", time->tm_hour, time->tm_min, time->tm_sec, (int)header->ts.tv_usec);
	cout << src_addr << " : " << src_port << " > " << dst_addr << " : " << dst_port << endl << endl;

	// vypsání (pouze) hlavičky, vynechání řádku
	printPacket((char*)packet, offset, 0);
	cout << endl;

	// vypsání obsahu
	printPacket((char*)packet, header->caplen, offset);
	cout << endl;
	return;
}
/**
 * @returns 0 všechno v pořádku
 * @returns 50 chyba při parsování argumentů
 * @returns 51 chyba při otvírání rozhraní
 * @returns 52 chyba při nastavení filtru
 * @returns 53 chyba při přijímání paketu
 */
int main(int argc, char** argv){
	pcap_t *handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 ip;

	// parsování argumentů
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
	
	// otevření rozhraní, nastavení filtru a vytvoření callback funkce
	// vytvořeno podle: https://www.tcpdump.org/pcap.html

	// otevření rozhraní (podle argumentu DEV) pro analyzování
	handle = pcap_open_live(arg.dev.data(), BUFSIZ, 0, 200, errbuff);
	if (handle == NULL) {
		cerr << "Couldn't open device " << errbuff << endl;
		return 51;
	}
	
	// nastavení filtru (podle řetězce v arg.filter), a jeho zkompilování
	if (pcap_lookupnet(arg.dev.data(), &ip, &mask, errbuff) == -1) {
		cerr << "Couldn't get netmask for device " << errbuff << endl;
		ip = 0;
		mask = 0;
	}
	if (pcap_compile(handle, &fp, arg.filter.data(), 0, ip) == -1) {
		cerr << "Couldn't parse filter " << pcap_geterr(handle) << endl;
		return 52;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		cerr << "Couldn't install filter" << pcap_geterr(handle) << endl;
		return 52;
	}
	

	// smyčka s callback funkcí
	// funkce callback() => vypsání paketu
	if (pcap_loop(handle, arg.num, callback, nullptr) != 0){
		cerr << "pcap_loop error : " << pcap_geterr(handle) << endl;
        return 53;
	}
	return 0;
}
// end ipk-sniffer.cpp
