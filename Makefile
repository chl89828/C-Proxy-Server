EXEC = proxy
OBJS = proxy_server.c
CC = gcc

all : proxy_server.c
	$(CC) -o $(EXEC) $(OBJS) -lcrypto
