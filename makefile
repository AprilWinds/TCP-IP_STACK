
tcp_stack : device.o init.o
	gcc -g -o tcp_stack device.o init.o -lpcap -pthread

device.o : device.c device.h common.h utils.h 	
	gcc -g -fgnu89-inline -c device.c

init.o : init.c  device.h
	gcc -g -c init.c

clean:
	rm -rf *.o
	rm -rf tcp_stack
