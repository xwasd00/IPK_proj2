CC=g++
LD=-lpcap
SRC=*.cpp
PROJ=ipk-sniffer
.PHONY:$(PROJ)
$(PROJ):
	$(CC) $(SRC) $(LD) -o $(PROJ)
