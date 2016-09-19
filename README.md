# picrypt
A relatively simple and easy to use tool that enables code protection
on Raspbery Pi related projects.

The main idea behind the project was conceived when I had to carry a couple of
raspberry pi sd cards, that contained important code, and I was worried about
loosing them.I needed a tool that would integrate seamlesly with the OS,
encrypt the code and automatically unlock it on boot-up. In addition it would
be it good to be able to protect the code from being run by not authorized
individuals or non authorized hardware.

## Features

* Protects projects from being cloned (Copy the SD card and put it in
another device)
* Protects projects from being copied over to other distribution and run even
in the same device.
* Minimal dependancies
* Encrypts a user specified directory and file names using Encrypts and
automatically unlocks them on start-up.
* Unlock key is stored in RAM so cannot be retrieved by read-ing the SD card
from an external machine.
* Code is bound to the softaware installation on the card and won't be unlocked
by moving it to a different OS, out of your controll.
* User defined salt and password generation routines, allowing finer controll
of the password generation logic.
* Binary is stripped from objectrs and contains no strings that can be used as
attack vectors.
* Provides Several layers of extra protection if required, using sofware id's
and sha1 of keyfiles.
* Contains basic anti debugging techinques that do NOT break the flow but
allert the user logic.
* The nature of the action when tamper detection triggers or when run on not
authorized hardware is left upon user's controll.
* Easy to configure and use.
* Contains a autocompile script that will detect the required hardware and
software parameters and build it.
* Using hash defines to modify code space based on parameters.
* Code is pre-processed before compillation to remove and hide sensitive
information.
* Can produce 8 and 16 Byte unlock codes.

## Planned Featrues

* Harware Dongle Key.
* Optional Password generation using the full ASCII charset.
* Automate the proccess of protecting multiple directories.
* Implement a systemd friendly unlock approach.

## Disclaimer

This is by no means a fool proof sollution. Since the system contains the key
and the lock on the same hardware there is nothing to stop a determined attacker
from breaking into it. I would not recommend using it on commercial IP
sollutions. This approach is meant to provide a layer of protection againist
simple attacks, and is mostly intended to be used in accademic and demo
projects.

### FAQ

* Why do you use some many defines?

-Because it allows versatility and fine tuning without having to modify
the code.

* My eyes hurt from those ifndef. Would it be better not to include them?

-Define guard serve two purposes. First the code does not break if you modify
or ommit parameters, and most importantly because it modifies the codespace,
it would be hard to produce a patcher that would work on every device using
this software.

* Why the added complexity with the user salt?

-Better explained by example. Imagine a simple mapping algorythm that maps a
letter to its next ASCII char. /etc/fstab would convert to 0fud0gtubc.
Knowing that / is repeated and always the root, finding the logic is as simple
as using a hex editior, find the printable chars, locating the repeating char
(0) and deduct it from what you expect it to be (/). From the refference table
48 -47 = 1. And the code is cracked. If the location of the string is not the
same for each user, (ifdefs) and the repeated char can be unique for every
user, it makes this attack more time consuming.

* If it can be cracked why bother?

-Everything can be cracked, especially a system containing the lock and the
key under the same unprotected space. There is a reason Raspbery Pi's are not
used in production projects. Unless there is a contained read proteted flash
memory it is impossible to hide something on an SD card. That being said, if
the effort of cracking something is greater than the payout, attackers will not
be bothered. Misplacing an SD card with your personal project protected by the
tool will most likely get it formatted and used to store  kitty pictures from
the internet. Just try not to loose it at an infosec convention...

* Why open source it if your logic can be used to attack it?

  -Because sharing is fun, and more minds are better than one.

* Can I use it to hide my banking details..

  -NO!

## Dependancies

~~~~~
build-essentail
libssl-dev
ecryptfs-utils
~~~~~

## Installation


Checkout the code

~~~~~
git clone && cd picrypt
~~~~~

Implement your own password generation logic.

~~~~~ f
nano/vim/atom usr_set_keygen.c
~~~~~

_The hash_high is only required if LONG_HASH is used_

If running on the target device autocompile will autofill the information for
the requested protecction level

~~~~~
./autocompile -c
~~~~~

For more options issue:

~~~~~
./autocompile -h
~~~~~

For manual compilation edit ```authorized_hwd.h```

There are 5 protection levels 4 of which are currently implemented.

1. CARE_BEAR:     No checks.
2. SCRIPT_KIDDY:  Chgecks the CPU serial of the board.
3. ARCH_USER:     Checks the CPU serial and the Linux software unique ID.
4. PEN_TESTER:    Check CPU Serial, Software ID and a user's defined file's SHA1
5. TIN_FOIL_HAT:  (Not implemented) Gets an extra key from a hardware dongle

Protection is implemented as a non teerminating flag, that will be asserted if
a single test defined by the protection level fails. It is up to the user's
discretion on what to do with it. I would highly recommend to NOT terminate the
program or print an error message, just modify the result to make brute force
harder.

Setting a protection level and NOT providing the required field for it on the
header is not critical and will not break the code. Not defined code will be
excluded from compillation and the associated test will not run, but if you try
to retrieve the datatype for it on the user method will cause a segfault
(bad bad things happen, and a fairy dies).

The header file requires define guards in order to compile:

~~~~~
#ifndef _HW_AUTH_H_
#define _HW_AUTH_H_

### Your definitions here ....

#endif
~~~~~

An example of a fully configured header file is included in the projects

~~~~~
#ifndef _HW_AUTH_H_
#define _HW_AUTH_H_
#define APP_ID     "FF112233"                         ///< Applcation ID
#define HWD_ID     "aabbccdd"                         ///< CPU_Serial
#define MACHINE_ID "4b7eaab33d5b1847a77aceb0550c3474" ///< Soft ID
#define FILE_SEED  "/etc/fstab"                       ///< File for SHA SEED
#define FILE_SHA1  "9b0412be89c672159deee5f041d9b60d24a3944f"///< sha of file
#define HWD_SRC     "/dev/ttyUSB0"                    ///< Port of HW dongle
#define PI_VER     3                                  ///< PI Board Version
#define PROTECTION PEN_TESTER                          ///< Level of protection

#define _STRHT_USR_SALT 0x71                          ///< Override String Salt

/* Special definitions  */
#define FAKE_SERIAL     0xaabbccdd                    ///< (Devel) Fake serial
//#define LONG_HASH                                   ///< 2x the passwd length
//#define DEVEL                                       ///< Developper build
#endif
~~~~~

Notes:

1. The CPU serial of the target device can be found by issuing /proc/cpuinfo
2. The software id can be found by issuing ```cat /etc/machine-id```
3. The sha1 can be found by issuing```sha1sum /etc/fstab```
4. PI_VER is the version of raspbeery pi, currently only 2 ad 3 are supported.
5. Setting STRHT_USR_SALT is optional but important because it will uniquely
maps your strings to an integer space.
6. Defining LONG_HASH will produce 16 Byte passwords
7. Fake serial is used to fix the result of serial detection method, to
facilitate development on PC.
8. DEVEL option turns on verbosity and breaks the code when the hardware
tests fail.
9. Note that APP_ID and HWD_SRC are not currently used and can be ommited.
10. Everything but the PI_VER, SALT and FAKE_SERIAL should be defined
as strings.

Finally compile and install.

~~~~~
Make clean
Make
Make install
~~~~~

Feeding the directory to codelock encrypts it.

~~~~~
codelock /opt/awesomeproject
~~~~~

## Accessing the Hardware Info structure in usr_set_keygen.c

The code will pass a structure containing all the collected information to
hash_low and hash_high methods, which need to be implemented by the user.
hash_low is the one setting the 8 low bytes (Big Endian Notation) and the
optional hash_high generates the 8 high bytes and is only used when LONG_HASH
is set.

The serial number and the boolean summary of the tests can be copied to local
values by dereferencing the pointiers

~~~~~
const uint64_t serial = *(uint64_t *)hwinfo_get_pl(hwinfo, HW_SERIAL);
const bool authorized = *(bool *)hwinfo_get_pl(hwinfo, HW_AUTHORIZED);
~~~~~

Wehn Authorized is set to false it could indicate that one or more of the tests
failed or the anti-tamper detection was trigger.


Strings are passed as a pointer, and do not need dereferencing.

~~~~~
const char *machine_id = (char *)hwinfo_get_pl(hwinfo, HW_MACHINE_ID);
const char *sha =  (char *)hwinfo_get_pl(hwinfo, HW_SHA1);
~~~~~

DO NOT use const char * comparison in those methods ie strcmp(sha,"aabbcc..")
since that will expose a sensitive string attacker.

Either convert them
to numbers or user _STRHT_ENCRPT_ macro to encypt it and _STRHT_CMP_ to compare
it in encrypted format.Use strhide_test.c or picrypt_main.c as refference.
