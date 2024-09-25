CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = aesdsocket
SRC = aesdsocket.c 
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) 

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)

default: all

.PHONY: all clean
