sdp_parser: sdp_parser.c
	gcc -Wall -g -o sdp_parser sdp_parser.c

clean:
	rm -f sdp_parser
