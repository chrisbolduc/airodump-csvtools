# Airodump CSV Tools
# by Christopher Bolduc

SRC = csvtools.c
BIN = csvtools

$(BIN) : $(SRC)
	gcc $(SRC) -o $(BIN)
