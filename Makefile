.PHONY: clean

all: oneway

oneway: main.o
	$(CXX) $(LDFLAGS) $^ $(shell pkg-config libcap_utils-0.7 --libs) -lssl -lcrypto -lrt -o $@

%.o: %.cpp Makefile
	$(CXX) $(CFLAGS) -Wall -std=c++0x $(shell pkg-config libcap_utils-0.7 --cflags) -c $< -o $@

clean:
	rm -rf oneway *.o
