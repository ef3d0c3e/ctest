NAME   := ctest
CC     := gcc
CFLAGS := -Wall -Wextra -rdynamic -D_GNU_SOURCE
LFLAGS := -lcapstone

SOURCES := $(wildcard src/*.c)
OBJECTS := $(addprefix objs/,$(SOURCES:.c=.o))

objs/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

libs/capstone/libcapstone.so.5:
	cd libs/capstone && CAPSTONE_STATIC=yes CAPSTONE_ARCHS="x86" ./make.sh

.PHONY: libs
libs: r
	libs/capstone/libcapstone.so.5

$(NAME): libs $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LFLAGS) -o $(NAME)

.PHONY: all
all: $(NAME)

.PHONY: clean
clean:
	rm -f $(OBJECTS)

.PHONY: docs
docs:
	@mkdir -p docs
	doxygen doxygen

.PHONY: fclean
fclean: clean
	rm -f $(NAME)
	rm -rf docs
	rm -rf site

.PHONY: re
re: fclean all
