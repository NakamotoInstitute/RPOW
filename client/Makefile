# Makefile for RPOW client

CFLAGS = -g -c -I. -I../common
LDFLAGS = -g

CLILIB = rpowclient.a

CLIOBJS =  rpowclient.o cryptchan.o certvalid.o util4758.o b64.o keys.o \
		rpio.o rpowutil.o connio.o libhc1.o gbignum.o

all: rpowcli

rpowcli: rpowcli.o $(CLILIB)
	gcc $(LDFLAGS) -o rpowcli rpowcli.o $(CLILIB) -lcrypto

$(CLILIB):	$(CLIOBJS)
	ar rcs $(CLILIB) $(CLIOBJS)

clean:
	-rm rpowcli rpowcli.o $(CLIOBJS) $(CLILIB)
