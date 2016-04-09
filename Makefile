CC = g++
CPFLAGS = -g -Wall -Wextra
LDFLAGS = -lm -lpcap -pthread

SRC = portScanner.cpp ps_lib.cpp ps_netw.cpp ps_scan.cpp
OBJ = $(SRC:.cpp=.o)
BIN = portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) $(OBJ) -o $(BIN)

%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)