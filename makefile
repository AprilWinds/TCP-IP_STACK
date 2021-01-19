
tcp_stack : device.o init.o
	gcc -o tcp_stack device.o init.o -lpcap -pthread

device.o : device.c device.h common.h
	gcc -c device.c

init.o : init.c init.h device.h
	gcc -c init.c

clean:
	rm -rf *.o
	rm -rf tcp_stack
