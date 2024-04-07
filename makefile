all: simDNSClient.c simDNSServer.c 
	gcc simDNSServer.c -o simDNSServer -lm
	gcc simDNSClient.c -o simDNSClient -lm

clean:
	rm simDNSServer simDNSClient 