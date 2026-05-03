CFLAGS = -O3 -DLUA_USE_POSIX -DLUA_USE_DLOPEN -fpic
LFLAGS = -shared -fpic
SO     = liblua.so
OBJS   = lapi.o lcode.o lctype.o ldebug.o ldo.o ldump.o lfunc.o lgc.o llex.o lmem.o lobject.o lopcodes.o lparser.o lstate.o lstring.o ltable.o ltm.o lundump.o lvm.o lzio.o lauxlib.o lbaselib.o lcorolib.o ldblib.o liolib.o lmathlib.o loadlib.o loslib.o lstrlib.o ltablib.o lutf8lib.o linit.o

copy: $(SO)
	cp $(SO) $(INSTALL_DIR)

$(SO): $(OBJS)
	$(CC) $(LFLAGS) -o $(SO) $(OBJS)

$(OBJS):
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f *.o
	rm -f *.so
