run: ipv4 ipv6

ipv4: IPV4_flood.c
	gcc -g -o ipv4 IPV4_flood.c
ipv6: IPV6_flood.c
	gcc -g -o ipv6 IPV6_flood.c
	
.PHONY: clean

clean:
	rm -f ipv4 ipv6
