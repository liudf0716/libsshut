CFLAGS += -Wall -fPIC

PREFIX=/usr/local
INCLUDEDIR=$(PREFIX)/include
LIBDIR=/lib/x86_64-linux-gnu/
LIBNAME=libsshut
DBGNAME=sshut_debug

DTARGET	= $(DBGNAME)
TARGET  = ${LIBNAME}.so
SOURCES = sshut.c sshut_action.c sshut_auth.c
HEADERS = sshut.h queue.h
OBJECTS = $(SOURCES:.c=.o)

DSOURCES = $(SOURCES) sshut_debug.c
DOBJECTS = $(DSOURCES:.c=.o)

all: $(TARGET) $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -fPIC -shared -o $(TARGET) $(OBJECTS)

$(DTARGET): $(DOBJECTS)
	$(CC) $(CFLAGS) -o $(DTARGET) $(DOBJECTS) -levent -lssh2

install:
	@echo "installation of $(LIBNAME)"
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(TARGET) $(LIBDIR)
	install -m 0644 $(HEADERS) $(INCLUDEDIR)

clean:
	rm -f $(TARGET) $(OBJECTS)

