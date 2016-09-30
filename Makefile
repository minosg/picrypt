#/****************************************************************************\
#* PiCrypt is a software key generator for ecryptfs locked system.            *
#* Since the program is meant to unlock the protected area, it has to be      *
#* decrypted itself but will perform a set of  hardware tests before producing*
#* the unlock key.                                                            *
#                                                                             *
#* Author: Minos Galanakis                                                    *
#* Email: minos197@gmail.com                                                  *
#* License: GPL v3.0                                                          *
#* Project: PiCrypt                                                           *
#* File Description: Project Make File                                        *
#\****************************************************************************/

CC=gcc
CFLAGS=-c -Wall -std=c99 -s
CFLAGS_DBG=-c -Wall -std=c99 -g
SSLFLAGS= -lssl -lcrypto

all: picrypt

picrypt : devel_disable namescrabbler_done ppprocessor strhide.o hwinfo.o \
usr_set_keygen.o adb.o lock.o picrypt_main.o picrypt.o
	$(CC)  strhide.o hwinfo.o usr_set_keygen.o picrypt_main.o picrypt.o adb.o \
	lock.o -o picrypt $(SSLFLAGS)

devel: devel_enable ppprocessor strhide.o hwinfo.o usr_set_keygen.o \
adb.o lock.o picrypt_main_devel.o picrypt.o
	$(CC)  strhide.o hwinfo.o usr_set_keygen.o picrypt_main_devel.o picrypt.o \
	adb.o lock.o -o picrypt $(SSLFLAGS)

ppprocessor : 	ppprocessor.o strhide.o
	$(CC) ppprocessor.o strhide.o -o ppprocessor
	./ppprocessor

devel_enable:
	sed -i "s:^//#define DEVEL:#define DEVEL:g" authorized_hwd.h

devel_disable:
	sed -i "s:^#define DEVEL://#define DEVEL:g" authorized_hwd.h

picrypt_main.o : picrypt_main.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) picrypt_main.c

picrypt_main_devel.o : picrypt_main.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS_DBG) picrypt_main.c -o picrypt_main_devel.o

picrypt.o :  picrypt.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) picrypt.c

hwinfo.o :  hwinfo.c hwinfo.h
	$(CC) $(CFLAGS) hwinfo.c

strhide.o : strhide.c strhide.h authorized_hwd.h
	$(CC) $(CFLAGS) strhide.c

ppprocessor.o: ppprocessor.c strhide.h authorized_hwd.h
	$(CC) $(CFLAGS) ppprocessor.c

usr_set_keygen.o :usr_set_keygen.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) usr_set_keygen.c

adb.o: adb.c adb.h
	$(CC) $(CFLAGS) adb.c

lock.o: lock.h lock.h
	$(CC) $(CFLAGS) lock.c

namescrabbler_done: namescrabbler
	./namescrabbler

install: picrypt
	cp ./picrypt /usr/bin

install_devel: devel
	cp ./picrypt /usr/bin

uninstall:
	rm -f /usr/bin/picrypt

automount_enable:
	@if [ -z "$(target)" ]; then\
		echo "Target directory is not set, set is using target=/path_to_dir";\
		exit 1;\
	fi
	@echo "[Unit]" >> /lib/systemd/system/picrypt.service
	@echo "Description=PiCrypt Key Creator" >> /lib/systemd/system/picrypt.service
	@echo "DefaultDependencies=no" >> /lib/systemd/system/picrypt.service
	@echo "After=sysinit.target" >> /lib/systemd/system/picrypt.service
	@echo "" >> /lib/systemd/system/picrypt.service
	@echo "[Install]" >> /lib/systemd/system/picrypt.service
	@echo "WantedBy=multi-user.target" >> /lib/systemd/system/picrypt.service
	@echo "" >> /lib/systemd/system/picrypt.service
	@echo "[Service]" >> /lib/systemd/system/picrypt.service
	@echo "TimeoutStartSec=0" >> /lib/systemd/system/picrypt.service
	@echo "Type=oneshot" >> /lib/systemd/system/picrypt.service
	@echo "ExecStart=/bin/sh -c '/usr/bin/picrypt \
	--mount $(target)'" >> /lib/systemd/system/picrypt.service
	systemctl daemon-reload
	systemctl enable picrypt

automount_disable:
	@systemctl disable picrypt
	@rm -rf /lib/systemd/system/picrypt.service
	@systemctl daemon-reload

automount_add:
	@if [ -z "$(target)" ]; then\
		echo "Target directory is not set, set is using target=/path_to_dir";\
		exit 1;\
	fi
	@echo "ExecStart=/bin/sh -c '/usr/bin/picrypt --mount \
	$(target)'" >> /lib/systemd/system/picrypt.service
	@systemctl daemon-reload

clean :
	rm -f *.o
	rm -f *.h.gch
	rm -f authorized_hwd_e.*
	rm -f namescrabbler_done
