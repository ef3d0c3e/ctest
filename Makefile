NAME   := ctest
CC     := gcc
CFLAGS := -Wall -Wextra -rdynamic -std=c23 -g -D_GNU_SOURCE

SOURCES := $(wildcard src/*.c)
OBJECTS := $(addprefix objs/,$(SOURCES:.c=.o))
INCLUDES := -Iincludes -I libs/capstone/include -I libs/elfutils

objs/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(NAME): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) \
		/home/baraquiel/Programming/ctests/libs/capstone/libcapstone.a \
		-ldw -lelf \
		-o $(NAME)

.PHONY: libs/capstone/libcapstone.a
libs/capstone/libcapstone.a:
	cd libs/capstone && \
	make

#.PHONY: libs/elfutils/libdwfl/libdwfl.a
#libs/elfutils/libdwfl/libdwfl.a:
#	cd libs/elfutils && \
#	autoreconf -i -f && \
#	./configure --enable-maintainer-mode && \
#	make

.PHONY: libs
libs: \
	libs/capstone/libcapstone.a
	#libs/elfutils/libdwfl/libdwfl.a

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
