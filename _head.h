#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include<time.h>

// sem
#include<sys/types.h>
#include<sys/sem.h>

// msg
#include<sys/msg.h>
#include<sys/ipc.h>

// shm 
#include<sys/ipc.h>
#include<sys/shm.h>


// sock
#include<errno.h>
#include<error.h>
#include<netdb.h> // gethostbyname 
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/socket.h>

#include<netinet/in.h>
#include<arpa/inet.h>


// linux_basicio 
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

// poll
#include<sys/poll.h>
// epoll
//#include<sys/epoll.h>


// advance io
#include<sys/uio.h>

// mmap
// not supoll by cygwin 
//#include<sys/mmap.h>

// process manager
#include<sys/wait.h>

// file and directory manager
#include<sys/stat.h>
#include<dirent.h>
#include<sys/types.h>

// file notify event listen
#include<sys/inotify.h>

// process signal
#include<signal.h>

// libc
#include<math.h>

// assert
#include<assert.h>

// timer
#include<sys/time.h>

// c++
#include<iostream>
using namespace std;


// socket

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
#include<string.h>
#include<time.h>

// shm 
#include<sys/ipc.h>
#include<sys/shm.h>

// sock
#include<errno.h>
#include<netdb.h>		// gethostbyname
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/socket.h>

#include<netinet/in.h>
#include<arpa/inet.h>


#define _errgo(condiction,label,mess) \
{	 \
	if(condiction)\
	{\
		perror(mess);\
		goto label;\
	}\
}

#define _error(condiction,mess) \
{	 \
	if(condiction)\
	{\
		printf("%s %d:%s\n note:%s\n",__FILE__,__LINE__,mess);\
		perror("");\
		return;\
	}\
} 
#define _error1(condiction,fmt,arg...) \
{	 \
	if(condiction)\
	{\
		printf("%s %d:",__FILE__,__LINE__);\
		printf(fmt,##arg);\
		perror("");\
		return;\
	}\
}
#define _exit(condiction,mess) \
{	 \
	if(condiction)\
	{\
		perror(mess);\
		exit(-1);\
	}\
} 

#define _pri printf


#define _ERROR(fmt)\
{\
	char buf[356];\
	snprintf(buf,sizeof(buf),"%s[%d] %s",__FILE__,__LINE__,fmt);\
	write(2,buf,strlen(buf));\
}
/*
#define _ERROR(fmt,arg...)\
{\
	char line[256];\
	snprintf(line,sizeof(line),fmt,##arg);\
	char debug[100];\
	snprintf(debug,sizeof(debug),"%s[%s] ",__file__,__LINE__);\
	char buf[356];\
	snprintf("%s %s",debug,buf);\
	write(2,buf,strlen(buf));\
}
*/

#define _INFO(fmt,arg...)\
{\
	char line[256];\
	snprintf(line,sizeof(line),fmt,##arg);\
	char debug[100];\
	snprintf(debug,sizeof(debug),"%s[%s] ",__file__,__LINE__);\
	char buf[356];\
	snprintf("%s %s",debug,buf);\
	write(1,buf,strlen(buf));\
}







