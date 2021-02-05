test : main.o DNSSearch.o include.o
	g++ -o test main.o DNSSearch.o include.o

main.o : main.cc include.h DNSSearch.h
	g++ -c main.cc

DNSSearch.o : DNSSearch.cc DNSSearch.h include.h
	g++ -c DNSSearch.cc

include.o : include.cc include.h
	g++ -c include.cc

clean :
	rm *.o