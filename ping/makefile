test : main.o ping.o
	g++ -o test main.o ping.o

main.o : main.cc ping.h
	g++ -c main.cc

ping.o : ping.cc ping.h
	g++ -c ping.cc

clean :
	rm *.o