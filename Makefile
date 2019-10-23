all: arp_spoof

arp_spoof: main.o getmy.o editpacket.o
	g++ -g -o arp_spoof main.o getmy.o editpacket.o -lpcap

getmy.o: getmy.cpp getmy.h
	g++ -g -c -o getmy.o getmy.cpp

editpacket.o: editpacket.cpp editpacket.h arpheader.h
	g++ -g -c -o editpacket.o editpacket.cpp

main.o: main.cpp arpheader.h getmy.h editpacket.h
	g++ -g -c -o main.o main.cpp

clean: 
	rm -f arp_spoof 
	rm -f *.o
