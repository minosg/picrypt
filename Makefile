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
CFLAGS=-c -Wall -std=c99
SSLFLAGS= -lssl -lcrypto

all: picrypt

picrypt : strhide.o hwinfo.o usr_set_keygen.o picrypt_main.o picrypt.o
	$(CC)  strhide.o hwinfo.o usr_set_keygen.o picrypt_main.o picrypt.o\
		-o picrypt $(SSLFLAGS)

picrypt_main.o : picrypt_main.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) picrypt_main.c

picrypt.o :  picrypt.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) picrypt.c

hwinfo.o :  hwinfo.c hwinfo.h
	$(CC) $(CFLAGS) hwinfo.c

strhide.o : strhide.c strhide.h authorized_hwd.h
	$(CC) $(CFLAGS) strhide.c



usr_set_keygen.o :usr_set_keygen.c picrypt.h authorized_hwd.h
	$(CC) $(CFLAGS) usr_set_keygen.c

clean :
	rm -f *.o
	rm -f *.h.gch