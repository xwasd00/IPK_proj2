# Síťový analyzátor
Síťový analyzátor do předmětu Počítačové komunikace a sítě, který na určitém síťovém rozhraní zachytává a filtruje pakety podle argumentů.
## Použití
`./ipk-sniffer -i DEV [-p PORT] [-t] [-p] [-n NUM]` případně `./ipk-sniffer --help` pro zobrazení nápovědy
## Parametry
 - `-h` nebo `--help` zobrazení nápovědy
 - `-i DEV` rozhraní, na kterém se bude poslouchat; není-li tento parametr uveden, vypíše se seznam aktivních rozhraní; není-li uveden DEV (avšak parametr -i je přítomen), vypíše se seznam aktivních rozhraní
 - `-p PORT` analyzátor bude filtrovat rozhraní na daném portu (ostatní ignoruje); není-li poarametr uveden, uvažují se všechny porty; chybí-li PORT, program skončí s návratovým kódem 50
 - `-t` nebo `--tcp` zobrazuje pouze tcp pakety
 - `-u` nebo `--udp` zobrazuje pouze udp pakety
 pokud není `--tcp` ani `--udp` specifikováno, uvažují se tcp a udp pakety zároveň; rovněž jsou-li přítomny oba parametry
 - `-n NUM` určuje počet paketů, které se mají zobrazit; pokud není uvedeno, zobrazí se pouze 1 paket; chybí-li NUM, program skončí s návratovým kódem 50
## Překlad
 -`make`
## Soubory
 - ipk-sniffer.cpp
 - Args.cpp
 - Args.h
 - Makefile
## Omezení
 - program nepřekládá adresy na doménová jména
