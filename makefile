GCC_TEST = /usr/bin/gcc-5.3/bin/gcc
ifeq ($(shell test -e $(GCC_TEST) && echo -n yes),yes)
CC    = $(GCC_TEST)
else
CC    = gcc
endif

GPP_TEST = /usr/bin/gcc-5.3/bin/g++
ifeq ($(shell test -e $(GPP_TEST) && echo -n yes),yes)
C++    = $(GPP_TEST)
else
C++    = g++
endif

LD_TEST = /usr/bin/gcc-5.3/bin/gcc
ifeq ($(shell test -e $(LD_TEST) && echo -n yes),yes)
LD    = $(LD_TEST)
else
LD    = gcc
endif

RM    = rm -f
STRIP = strip

DAEMON_SRCS = web_mtqq_gateway.c dexec.c ip_acl.c dnonblock.c dsignal.c dfork.c dpid.c dlog.c dmem.c array.c jlog.c content_types.c x_http.c x_functions.c x_session.c x_md5.c mqtt.c version.c

DAEMON_TARGET = web_mtqq_gateway

all:	daemon
	

#######################
G_EX = $(shell git describe --tag 2> /dev/null ; if [ $$? -eq 0 ]; then echo "OK"; else echo "FAIL" ; fi)
GVER = $(shell git describe --abbrev=7 --long 2>/dev/null)
#######################

version.c: FORCE
	@echo "==============================================="
	@echo "git present:" $(G_EX) " ver:" $(GVER)
	@echo "==============================================="
ifeq "$(G_EX)" "OK"
	git describe --tag | awk 'BEGIN { FS="-" } {print "#include \"version.h\""} {print "const char * git_version = \"" $$1"."$$2"\";"} END {}' > version.c
	git rev-parse --abbrev-ref HEAD | awk '{print "const char * git_branch = \""$$0"\";"} {}' >> version.c
endif

FORCE:

CFLAGS = -std=c11 -MD -MP  -Wall -Wfatal-errors -Wno-unused-function 
#-fPIC 

daemon: $(DAEMON_TARGET)
daemon: CFLAGS += -ggdb



DAEMON_OBJS = $(DAEMON_SRCS:.c=.o)
DAEMON_DEPS = $(DAEMON_SRCS:%.c=%.d)

LIBS_DAEMON = $(shell pkg-config --libs libmicrohttpd) $(shell pkg-config --libs libssl) $(shell pkg-config --libs libcrypto) -ldl -ljson-c -lzip -ldl -lpthread -lmosquitto


daemon_debug: $(DAEMON_TARGET)
daemon_debug: CFLAGS += -DDEBUG -O0 -ggdb -fsanitize=leak -fno-omit-frame-pointer -fPIE -pie -fsanitize=address
daemon_debug: LDFLAGS += -Wl,-rpath=/usr/bin/gcc-5.3/lib64/ -lasan

$(DAEMON_TARGET): $(DAEMON_OBJS) $(COMMON_OBJS)
	$(CC) -o $(DAEMON_TARGET) $(DAEMON_OBJS) $(COMMON_OBJS) $(LDFLAGS) $(LIBS_DAEMON)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

-include $(DEPS)
-include $(TARGET_DEPS)
-include $(LIBDEPS)
-include $(DAEMON_DEPS)
-include $(COMMON_DEPS)


#DESTDIR=
prefix=/usr
bindir=/sbin
sysconfdir=/etc

MKDIR_P = mkdir -p
ETC_DIR = $(DESTDIR)$(sysconfdir)/web_mtqq_gateway.d

.PHONY: directories

directories: ${ETC_DIR}

${ETC_DIR}:
	${MKDIR_P} ${ETC_DIR}

cleandaemon_debug: clean 

cleanall: clean

clean:
	rm -f $(DAEMON_DEPS) $(DAEMON_OBJS) $(DAEMON_TARGET) core* 


daemon_install: daemon
	install -D $(DAEMON_TARGET) $(DESTDIR)$(prefix)$(bindir)/$(DAEMON_TARGET)


install: daemon_install directories
	install -m 644 -D ./systemd/web_mtqq_gateway.service $(DESTDIR)/lib/systemd/system/web_mtqq_gateway.service
	if test -f $(DESTDIR)/etc/sysconfig/web_mtqq_gateway; then echo "Already exists"; else install -m 644 -C -D ./systemd/web_mtqq_gateway $(DESTDIR)/etc/sysconfig/web_mtqq_gateway; fi; \
	systemctl daemon-reload | true
