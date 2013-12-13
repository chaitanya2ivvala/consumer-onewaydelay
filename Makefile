rev:=$(shell git log --pretty=format:'%h' -n 1)

.PHONY: clean

all: oneway

oneway: main.o 
	$(CXX) $(LDFLAGS) $^ $(shell pkg-config libcap_utils-0.7 --libs) -lssl -lcrypto -lrt -o $@

%.o: %.cpp %.hpp Makefile 
	$(CXX) $(CFLAGS) -Wall -std=c++0x $(shell pkg-config libcap_utils-0.7 --cflags) -c $< -o $@

clean:
	rm -rf oneway *.o owd-*.tar.gz

dist:	owd-$(rev).tar.gz

owd-$(rev).tar.gz:
	git archive --prefix=owd-$(rev)/ -o owd-$(rev).tar.gz master

main.cpp: printpkt.hpp
