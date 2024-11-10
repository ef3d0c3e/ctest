NAME   := ctest
CC     := gcc
CFLAGS := -Wall -Wextra -rdynamic -std=c23 -D_GNU_SOURCE
LFLAGS := -lcapstone

SOURCES := $(wildcard src/*.c)
OBJECTS := $(addprefix objs/,$(SOURCES:.c=.o))

objs/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJECTS)
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
