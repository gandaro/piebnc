CC	= gcc
LD	= gcc
CFLAGS	= -Wall -ggdb

all:	$(OBJS)
	@echo Initializing bouncer compilation
	@echo [*] Running Conversion Tool for older psyBNC Data.
	@$(CC) tools/convconf.c -o tools/convconf
	@tools/convconf
	@echo [*] Running Autoconfig.
	@$(CC) -I. tools/autoconf.c -o tools/autoconf -DCC=\"$(CC)\"
	@tools/autoconf
	@echo [*] Compiling MakeSalt for Encryption..
	@$(CC) -I. -o makesalt tools/makesalt.c
	@./makesalt
	@echo [*] Compiling Bouncer..
	@make -f makefile.out
	@ls -al psybnc
	@echo done.

autoconf:
	@echo [*] Running Autoconfig.
	@rm -f tools/autoconf
	@$(CC) -I. tools/autoconf.c -o tools/autoconf -DCC=\"$(CC)\"
	@tools/autoconf
	
menuconfig:
	@echo Initializing Menu-Configuration
	@echo [*] Running Conversion Tool for older psyBNC Data.
	@$(CC) tools/convconf.c -o tools/convconf
	@tools/convconf
	@echo [*] Running Autoconfig.
	@$(CC) -I. tools/autoconf.c -o tools/autoconf -DCC=\"$(CC)\"
	@tools/autoconf
	@echo [*] Creating Menu, please wait.
	@echo This needs the 'ncurses' library. If it is not available, menuconf wont work. If you are using 'curses', use make menuconfig-curses instead.
	@$(CC) menuconf/menuconf.c menuconf/inputbox.c menuconf/util.c menuconf/checklist.c menuconf/menubox.c menuconf/textbox.c src/snprintf.c $(CFLAGS) -I. -lncurses -lm -o menuconf/menuconf
# 2>/dev/null
	@menuconf/menuconf
	@clear
	@echo Now compile psyBNC using make, if not yet compiled, or if Options were changed.
	@echo done.

menuconfig-curses:
	@echo Initializing Menu-Configuration using Curses
	@echo [*] Running Conversion Tool for older psyBNC Data.
	@$(CC) tools/convconf.c -o tools/convconf
	@tools/convconf
	@echo [*] Running Autoconfig.
	@$(CC) -I. tools/autoconf.c -o tools/autoconf -DCC=\"$(CC)\"
	@tools/autoconf
	@echo [*] Creating Menu, please wait.
	@echo This needs the 'curses' library. If it is not available, menuconf wont work.
	@$(CC) menuconf/menuconf.c menuconf/inputbox.c menuconf/util.c menuconf/checklist.c menuconf/menubox.c menuconf/textbox.c src/snprintf.c -DNONCURSES -I. -lcurses -lm -o menuconf/menuconf 2>/dev/null
	@menuconf/menuconf
	@clear
	@echo Now compile psyBNC using make, if not yet compiled, or if Options were changed.
	@echo done.

c-ares: src/c-ares/.libs/libcares.a c-ares-done

src/c-ares/.libs/libcares.a:
	@echo Configuring and building c-ares, this can take a while..
	cd src/c-ares && make clean; ./configure --disable-shared --enable-static && make
	@echo

c-ares-done:
	@echo The c-ares library has been built successfully. You can now compile psyBNC.

dist:
	cd ..; tar -cvf psyBNC2.4.tar psybnc; gzip -c psyBNC2.4.tar > psyBNC2.4.tar.gz; rm psyBNC2.4.tar

clean:
	@echo Cleaning.
	rm -rf src/*.o
	rm -f psybnc menuconf/menuconf tools/autoconf tools/makesalt tools/sys tools/convconf
	rm -f tools/chkbind tools/chkdns tools/chkenv tools/chkipv6 tools/chkmysql tools/chkresolv
	rm -f tools/chksock tools/chkssl tools/chkmysql tools/chktime tools/chkdns
