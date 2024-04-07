all: dnsclient.c dnsserver.c 
	gcc dnsserver.c -o server -lm
	gcc dnsclient.c -o client -lm
	./server 9009

clean:
	rm server client 