// třída pro zpracování argumentů ke 2. projekti do IPK
// Michal Sova (xsovam00)

#include "Args.h"
using namespace std;

/**
 * @brief funkce pro získání argumentů a upravení chování programu
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @returns 0 pokud proběhne parsování bez problému
 * @returns -1 v případě vypsání rozhraní
 * @returns 50 jinak
 * */
int Args::getOpts(int argc, char** argv){
	
	// nejsou žádné argumenty -> vypsání možných rozhraní
	if(argc < 2){
		printDevs();
		return -1;
	}


	// Předloha z: https://codeyarns.com/2015/01/30/how-to-parse-program-options-in-c-using-getopt_long/
	// dlouhé možnosti
	const option longopts[] = {
		{"tcp", no_argument, nullptr, 't'},
		{"udp", no_argument, nullptr, 'u'},
		{"help", no_argument, nullptr, 'h'}};
	int option;

	// získání možností z getopt_long 
	while((option = getopt_long(argc, argv, ":i:p:tun:h", longopts, nullptr)) != -1){
		switch(option){

			// ./ipk-sniffer -i DEV
			// kde DEV je název rozhraní (např. eth0)
        	case 'i':
				dev = optarg;
				break;

			// ./ipk-sniffer -i DEV -p PORT
			// kde PORT je číslo portu, na kterém bude analyzátor zachytávat pakety
			case 'p':
				port = stoi(optarg);
				break;

			// -t nebo --tcp: je-li tento argument přítomný, 
			// analyzátor bude zachytávat pouze pakety s tcp protokolem
			case 't':
				tcp = true;
				break;

			// -u nebo --udp: je-li tento argument přítomný, 
			// analyzátor bude zachytávat pouze pakety s udp protokolem, 
			// je-li přítomný --udp i --tcp, analyzátor bude zachytávat 
			// oba druhy paketů s danými protokoly
			case 'u':
				udp = true;
				break;

			// ./ipk-sniffer -i DEV -n NUM
			// kde NUM je počet zachycených paketů analyzátorem
			case 'n':
				num = stoi(optarg);
				break;
			
			// ./ipk-sniffer --help
			// vytisknutí nápovědy
			case 'h':
				printHelp();
				return -1;
				break;
			
			// chybí hodnota možnosti (např. -p PORT)
			// v případě argumentu -i bez hodnoty vypíše názvy možných rozhraní
			case ':':
				if(optopt == 'i'){
					printDevs();
					return -1;
				}
				cerr << "možnost " << optopt << " potřebuje hodnotu" <<endl;
				return 50;
				break;

			// neznámé možnosti filtr ignoruje
			default:
				break;
		}
	}
	// konec využití předlohy


	// chybí argument -i DEV -> vypsání rozhraní
	if( dev.size() == 0 ){
		printDevs();
		return -1;
	}

	// nastavení filtru (tcp, udp, port)
	setFilter();
	return 0;
}
/**
 * @brief vypsání možných rozhraní
 * */
void Args::printDevs(){
	
	// v případě chyby se zde vypíše chybové hlášení
	char errbuff[PCAP_ERRBUF_SIZE];
	// seznam rozhraní
	pcap_if_t *alldevs;
	
	// najití rozhraní pomocí funkce pcap_findalldevs
	if (pcap_findalldevs(&alldevs, errbuff) != 0){
		cerr << "pcap_findalldevs error: " << errbuff << endl;
	}

	// vypsání rozhraní s krátkým popiskem (pokud je přítomen)
	pcap_if_t *dev = alldevs;
	while (dev != NULL){

		// jméno rozhraní
		cout << dev->name;

		// popis
		if(dev->description != NULL){
			cout << " : " << dev->description;
		}
		cout << endl;

		// další roazhraní
		dev = dev->next;
	}

	// uvolnění paměti
	pcap_freealldevs(alldevs);
	return;
}
/**
 * @brief funkce pro vypsání nápovědy
 * */
void Args::printHelp(){
	cout << "použití: `./ipk-sniffer -i DEV [-p PORT] [-t] [-p] [-n NUM]` případně `./ipk-sniffer --help` pro zobrazení této nápovědy" << endl;
	cout << "argumenty:" << endl;
	cout << "	`-h` nebo `--help` zobrazení nápovědy" << endl;
	cout << "	`-i DEV` rozhraní, na kterém se bude poslouchat; není-li tento parametr uveden, vypíše se seznam aktivních rozhraní" << endl;
	cout << "	`-p PORT` analyzátor bude filtrovat rozhraní na daném portu (ostatní ignoruje); není-li poarametr uveden, uvažují se všechny porty" << endl;
	cout << "	`-t` nebo `--tcp` zobrazuje pouze tcp pakety" << endl;
	cout << "	`-u` nebo `--udp` zobrazuje pouze udp pakety" << endl;
	cout << "	`-n NUM` určuje počet paketů, které se mají zobrazit; pokud není uvedeno, zobrazí se pouze 1 paket" << endl;
	return;
}
/**
 * @brief funkce na nastavení filtru pro funkci pcap_lookupnet
 * */
void Args::setFilter(){

	// port byl zadán (výchzí hodnota: -1)
	if(port > 0){

		// nebyl zadán ani jeden nebo byly zadány oba dva
		if(!(udp ^ tcp)){
            filter = "tcp port ";
			filter.append(to_string(port));
            filter.append(" or udp port ");
        }
		// byl zadán jen tcp protokol
        else if (tcp){
            filter = "tcp port ";
        }
		// byl zadán jen udp protokol
        else {
            filter = "udp port ";
        }

		//přidání portu
		filter.append(to_string(port));
	}
	// port nezadán -> všechny porty
	else{

		// nebyl zadán ani jeden nebo byly zadány oba dva
		if(!(udp ^ tcp)){
			filter = "tcp or udp";
		}

		// byl zadán jen tcp protokol
		else if (tcp){
			filter = "tcp";
		}

		// byl zadán jen udp protokol
		else{
			filter = "udp";
		}
	}
	return;
}
// end Args.cpp
