CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = writer
SRC = writer.c 
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) 

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
