//
// Created by michal on 28.04.20.
//

#ifndef IPK_ARGS_H
#define IPK_ARGS_H
#include <getopt.h>
#include <iostream>
#include <pcap.h>

class Args {
public:
	std::string dev;
	std::string filter;
	int num = 1;
	int port = -1;
	bool tcp = false;
	bool udp = false;

	int getOpts(int, char**);
	void printDevs();
	void setFilter();

};


#endif //IPK_ARGS_H
