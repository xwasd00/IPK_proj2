#ifndef IPK_ARGS_H
#define IPK_ARGS_H
#include <getopt.h>
#include <iostream>
#include <pcap.h>

// třída pro zpracování argumentů ke 2. projekti do IPK
// Michal Sova (xsovam00)
// Využití funkce getopt_long inspirováno příkladem:https://codeyarns.com/2015/01/30/how-to-parse-program-options-in-c-using-getopt_long/

class Args {
	
	// zachytávání paketů s tcp/udp protokolem
	// pokud jsou oba nastaveny na false, znamená to, že nebyl specifikován výběr a 
	// analyzátor bude zachytávat oba
	bool tcp = false;
	bool udp = false;

	// port, na kterém má analyzátor zachytávat pakety
	// záporné číslo značí všechny porty
	int port = -1;

public:

	// název rozhraní, na kterém se budou pakety zachytávat
	std::string dev;

	// filtr pro funkci pcap_lookupnet pro nastavení analyzátoru 
	// na jakém portu a které pakety bude zachytávat
	std::string filter;

	// počet zachytávaných paketů
	int num = 1;

	// funkce pro získání argumentů a upravení chování programu
	// v případě vypsání rozhraní vrací funkce -1
	// pokud proběhne parsování bez problému, vrrací funkce 0
	// jinak 1
	int getOpts(int, char**);

	// vytisknutí možných rozhraní
	void printDevs();
	
	// funkce pro vypsání nápovědy
	void printHelp();
	
	// funkce na nastavení filtru pro funkci pcap_lookupnet
	void setFilter();

};


#endif //IPK_ARGS_H
