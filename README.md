# picrypt
A relatively simple and easy to use tool that enables code protection
on Raspbery Pi related projects.

The main idea behind the project was conceived when I had to carry a couple of
raspberry pi SD cards, that contained important code, and I was worried about
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
* Binary is stripped from objects and contains no strings that can be used as
attack vectors.
* Provides Several layers of extra protection if required, using sofware id's
and sha1 of keyfiles.
* Contains basic anti-debugging techinques that do NOT break the flow but
allert the user logic.
* Easy to configure and use.
* Contains a auto-compile script that will detect the required hardware and
software parameters and build it.
* Using hash defines to modify code space based on parameters.
* Code is pre-processed before compillation to remove and hide sensitive
information.
* Can produce 8 and 16 chars unlock codes in the fulla printable ASCII range.
* Supports encryption of multiple directories using the same key.
* Systemd suport, directories can be automatically unlocked on start-up.
* Supports custom user input from command line, with an authentication token as
extra security againist bruteforce attacks.

## Planned Featrues

* Harware Dongle Key.
* ~~Optional Password generation using the full ASCII charset.~~
* ~~Automate the proccess of protecting multiple directories.~~
* ~~Implement a systemd friendly unlock approach.~~

## Disclaimer

This is by no means a fool proof sollution. Since the system contains the key
and the lock on the same hardware there is nothing to stop a determined attacker
from breaking into it. I would not recommend using it on commercial IP
sollutions. This approach is meant to provide a layer of protection againist
simple attacks, and is mostly intended to be used in accademic and demo
projects.

### FAQ

* Why do you use some many defines?

 - Because it allows versatility and fine tuning without having to modify
the code.


* My eyes hurt from those ifndef. Would it be better not to include them?

 - Define guard serve two purposes. First the code does not break if you modify
or ommit parameters, and most importantly because it modifies the codespace,
it would be harder to produce a patcher that would work on every device using
this software.


* Why the added complexity with the user salt?

 - Better to explained by example. Imagine a simple mapping algorythm that maps a
letter to its next ASCII char. /etc/fstab would convert to 0fud0gtubc.
Knowing that / is repeated and always the root, finding the logic is as simple
as using a hex editior, find the printable chars, locating the repeating char
(0) and deduct it from what you expect it to be (/). From the refference table
48 -47 = 1. And the code is cracked. If the location of the string is not the
same for each user, (ifdefs) and the repeated char can be unique for every
user, it makes this attack more time consuming.


* If it can be cracked why bother?

 - Everything can be cracked, especially a system containing the lock and the
  key under the same unprotected space. There is a reason Raspbery Pi's are not
  used in production projects. Unless there is a contained read proteted flash
  memory it is impossible to hide something on an SD card. That being said, if
  the effort of cracking something is greater than the payout, attackers will not
  be bothered. Misplacing an SD card with your personal project protected by the
  tool will most likely get it formatted and used to store  kitty pictures from
  the internet. Just try not to loose it at an infosec convention...


* How can I protect my sensitive variable names?

 - If you do wish to use intuitive names in your method implementation, you can
  set them to be randomly named by adding them to the namescrabbler list. Do not
  use that for common words that are contained in other variables i.e DO NOT
  scamble a variable named re. This trick only works if the variables are UNIQUE
  since it is calling sed to do insline replacement.


* Do I really need to write code to handle anti-tamper and authorized flags?.

  - Depends. Mostly on how secure would you like your code to be. Not checking
  the protection flags, will enable anyone to step through your hash calculation
  routine and reverse engineer the logic. Make a fake logic and user a Finite
  state machine logic to separate actual code to fake code. Do not forget to add
  sensitive variables and functions to namescrabbler.


* Why open source it if your logic can be used to attack it?

  - Because code is meant to be shared.

* Can I use it to hide my banking details..

  -NO! Do you use permament markets to write the password on your cards?

## Dependancies

The following packages are required to build and run on Raspbian/Debian variant:

~~~~~
build-essentail
libssl-dev
ecryptfs-utils
~~~~~


## Quick Install summary

Checkout the code:

~~~~~
git clone && cd picrypt
~~~~~

Implement your own password generation logic:

~~~~~
nano/vim/atom usr_set_keygen.c
~~~~~

*The hash_high method is only required if LONG_HASH is used*

If running on the target device autocompile will autofill the information for
the requested protection level:

~~~~~
./autocompile -c
~~~~~

# Accessing the Hardware Info structure in ```usr_set_keygen.c```

The code will pass a structure containing all the collected information to
hash_low and hash_high methods, which need to be implemented by the user.
hash_low is the one setting the 8 low bytes (Big Endian Notation) and the
optional hash_high generates the 8 high bytes and is only used when LONG_HASH
is set.

*User methods have been updated to produce output in ASCII RANGE so the above
is valid only when the hash is representing bytes*

It is important to note that user set methods will be called once or twice
during code execution
* Once if the anti-tamper flag is not asserted
* Twice if the system detects a debugger. Being run through a debugger means
someone is looking closer into the logic of the binary. for that purpose the
user defined function is being called BEFORE any of the other fields are parsed
enabling the user terminate the program and protect the hardcoded values.

The serial number and the boolean summary of the tests can be copied to local
values by dereferencing the pointers

~~~~~
const uint64_t serial = *(uint64_t *)hwinfo_get_pl(hwinfo, HW_SERIAL);
const bool authorized = *(bool *)hwinfo_get_pl(hwinfo, HW_AUTHORIZED);
~~~~~

When authorized is set to false it could indicate that one or more of the tests
failed.


Strings are passed as a pointer, and do not need dereferencing.

~~~~~
const char *machine_id = (char *)hwinfo_get_pl(hwinfo, HW_MACHINE_ID);
const char *sha =  (char *)hwinfo_get_pl(hwinfo, HW_SHA1);
~~~~~

DO NOT use const char * comparison in those methods ie strcmp(sha,"aabbcc..")
since that will expose a sensitive strings to code inspection.

Either convert them
to numbers or user ```_STRHT_ENCRPT_``` macro to encypt it and
```_STRHT_CMP_```  to compare it in encrypted format.Use strhide_test.c or
picrypt_main.c as reference.

A set of macros is also provided for convenience:

~~~~~
const bool authorized = _USRST_AUTHORIZED_;
const bool anti-tamper =  _USRST_ANTI_TAMPER_;
const uint64_t serial = _USRST_SERIAL_ ;
const char *machine_id = _USRST_MACHINEID_;
const char *sha =  _USRST_SHA1_;
const char *input = _USRST_UINPT_;
~~~~~

The custom command line arguments will be inlcuded only and if only the Token
has been matched to the hardcoded one. It is advised to check for NULL when
parsing that information.

~~~~~
/* Print user input if set */
const char *input = _USRST_UINPT_;
if (input != NULL) printf("User Input %s\n", input);
~~~~~

## Manual complilation

For manual compilation edit ```authorized_hwd.h```

There are 5 protection levels 4 of which are currently implemented.

1. ```CARE_BEAR```:     No checks.
2. ```SCRIPT_KIDDY```:  Checks the CPU serial of the board.
3. ```ARCH_USER```:     Checks the CPU serial and the Linux software unique ID.
4. ```PEN_TESTER```:    Check CPU Serial, Software ID and a user's defined file's SHA1
5. ```TIN_FOIL_HAT```:  (Not implemented) Gets an extra key from a hardware dongle

Protection is implemented as a non execution terminating flag, that will
be asserted if a single test defined by the protection level fails.
It is up to the user's discretion on what to do with it.
I would highly recommend to NOT exit the program while printng an error message,
just modify the result to make brute force harder.

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
#define INPT_TOKEN "knockknock"                       ///< Permit input from cmd

#define _STRHT_USR_SALT 0x71                          ///< Override String Salt

/* Special definitions  */
#define FAKE_SERIAL     0xaabbccdd                    ///< (Devel) Fake serial
//#define LONG_HASH                                   ///< 2x the passwd length
//#define DEVEL                                       ///< Developper build
#endif
~~~~~

Notes:

1. The CPU serial of the target device can be found by
issuing ```cat /proc/cpuinfo | grep Serial | awk '{print $3}'```
2. The software id can be found by issuing ```cat /etc/machine-id```
3. The sha1 can be found by issuing```sha1sum /etc/fstab```
4. PI_VER is the version of raspbeery pi, currently only 2 ad 3 are supported.
5. Setting STRHT_USR_SALT is optional but important because it will uniquely
map your strings to an integer symbol space.
6. Defining LONG_HASH will produce 16 Byte passwords
7. Fake serial is used to fix the result of serial detection method, to
facilitate development on PC.
8. DEVEL option turns on verbosity and breaks the code when the hardware
tests fail.
9. Note that APP_ID and HWD_SRC are not currently used and can be ommited.
10. Everything but the PI_VER, SALT and FAKE_SERIAL should be defined
as strings.
11. INPT_TOKEN is a command line anti-bruteforce autentication.Any input
arguments that do not contain the correct token will be ignored

Finally compile and install.

~~~~~
make clean
make
sudo Make install
~~~~~

**ALWAYS** clean and git reset after a normal make, since namescrabbler will heavily
modify the files. User code in usr_set_keygen should be commited
on your build branch before doing so.

~~~~~
git config user.name "Your Name" && git config user.email "me@somemail.com"
git add usr_set_keygen.c && git commit -m "My encryption algorythm"
make clean
git reset --hard
~~~~~

Assuming authorized_hwd.h has the commented out entry of ```//#define DEVEL```,
you can invoke a development build for increased verbosity.

~~~~~
make clean & make devel
gdb ...
sudo make install_devel
~~~~~

Development builds are usefull because they do not scramble fucntion and
variable names, and they contain extra verbosity.

_Running gdb in arm architecture with libcrypt will crash unless gdb is asked
to ignore SIGILL: _

 ```handle SIGILL nostop noprint```


## Autocompile

Autocompile is a simple helper that will automatically collect the hardware
information and compile the binary for the host system.A copy of the binary
will also be moved into the bin folder.

By default it generates an 8 byte password, with ```PEN_TESTER``` level of protection.

Since this level requires a keyfile, if it is not specified by the user, it will
build a list and randomly choose, asking user to verify it. Once a file is
selected, the system will create an exact copy with a different name, and use
that as the keyfile.

Altenatively a keyfile can be specified with the ```-k /absolute_path/filename```
argument.

Full list of supported arguments:

~~~~~
./autocompile -h
-h, --help            show this help message and exit
--reset, -r           Reset current units machine-id
--compile, -c         Compile all
--keyfile KEYFILE, -k KEYFILE
                     Use file as sha1 keyfile
--lhash, -l           create double length password
--nobackup, -n        Remove authorized_hardware.h and don't restore
--fake FAKE_SERIAL, -f FAKE_SERIAL
                     Add a fake serial to detection method
--devel, -d           Executable will print out auth failures
--protection PROTECTION, -p PROTECTION
                     Set the protection level
--bulk BULK, -b BULK  Set Bulk compile directory (Not Implemented)
~~~~~

It is recommended to issue ```--reset``` when compiling at a device booted from  a
cloned SD card image, since that will regenerate a new unique machine-id
for that device.

By default the scripts attempts to respect any authorized_hwd.h files the user
has, to back it up and restore it after all operataions have completed. The
```--nobackup``` directive will just overwrite the file and not restore it.

## Encrypting/ Decrypting directories

In order to encrypt one or more directories use the similarly named directive

~~~~~
sudo picrypt --encrypt /opt/your_awesome_code
sudo picrypt --encrypt /opt/code_you_are_ashamed_of
~~~~~

In order to mount a previously encrypted directory use the mount directive

~~~~~~
sudo picrypt --mount /opt/your_awesome_code
sudo picrypt --mount /opt/code_you_are_ashamed_of
~~~~~~

** Both encrypt and mount directives assume that the caller has su priviledges,
that he provided an absolute path, and that ecryptfs-utils is installed onto
the system **

## Automatically mount directory/ies on start-up

Makefile can create systemd hooks that will automount encrypted directories
The first call will create the unit file for the directory specified as target:

~~~~~~
sudo make automount_enable target=/opt/your_awesome_code
~~~~~~

Additional directories can be added using the add directive:

~~~~~~
sudo make automount_add target=/opt/code_you_are_ashamed_of
...
~~~~~~

Automount can be disabled by calling automount_disable:

~~~~~~
sudo make automount_disable
~~~~~~

## Passing in arguments to the user logic.

Picrypt supports custom user input using the --input directive. Before passing
on the arguemnts to the hash function, it will compare the provided keyword(token)
againist the one set in the authorized_hwd.h. If they match, the next arguments
is being passsed as custom argument.

The position of the ```--input``` arguemnt is not important as long as two extra
arguments follow it.

~~~~~~
picrypt --vhash --input knockknock whoisthere
picrypt --input knockknock whoisthere
~~~~~~

Both arguemnts will pass *whoishtere* to the user_set_keygen.c methods.
