//
// 
//

#include "Args.h"
using namespace std;
int Args::getOpts(int argc, char** argv){
	if(argc < 2){
		printDevs();
		return -1;
	}
	const option longopts[] = {
		{"tcp", no_argument, nullptr, 't'},
		{"udp", no_argument, nullptr, 'u'}};
	int option;
	while((option = getopt_long(argc, argv, ":i:p:tun:", longopts, nullptr)) != -1){
      switch(option){
         case 'i':
			dev = optarg;
			break;
         case 'p':
			port = stoi(optarg);
			break;
         case 't':
		 	tcp = true;
            break;
         case 'u':
		 	udp = true;
            break;
         case 'n':
			num = stoi(optarg);
            break;
         case ':':
		 	if(optopt == 'i'){
				printDevs();
				return -1;
			}
            cerr << "option " << optopt << " needs a value" <<endl;
			return 1;
            break;
         case '?':
            cout << "unknown option: " << optopt << endl;
			return 1;
            break;
      }
   }
   setFilter();
   return 0;
}
void Args::printDevs(){
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	if (pcap_findalldevs(&alldevs, errbuff) != 0){
		cerr << "pcap_findalldevs error" << errbuff << endl;
	}
	pcap_if_t *dev = alldevs;
	while (dev != NULL){
		cout << dev->name;
		if(dev->description != NULL){
			cout << " : " << dev->description;
		}
		cout << endl;
		dev = dev->next;
	}
	pcap_freealldevs(alldevs);
}
void Args::setFilter(){
	if(port > 0){
		if(!(udp ^ tcp)){
            filter = "tcp port ";
			filter.append(to_string(port));
            filter.append(" or udp port ");
        }
        else if (tcp){
            filter = "tcp port ";
        }
        else{
            filter = "udp port ";
        }
		filter.append(to_string(port));
	}
	else{
		if(!(udp ^ tcp)){
			filter = "tcp or udp";
		}
		else if (tcp){
			filter = "tcp";
		}
		else{
			filter = "udp";
		}
	}
	cout << filter << endl;
}
