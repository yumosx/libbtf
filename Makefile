.PHONY: all clean
HEADERS = btf.h
SRCS = 	 btf.c main.c

CFLAGS = -Wall -g

OBJS = $(SRCS:.c=.o)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) -o btf $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) btf