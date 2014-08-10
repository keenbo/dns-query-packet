BASE_INC_PATH= 
BASE_LIB_PATH=
LDLIBS += -lpthread -I.
# global flage -Wall -g -O2 
# -I{inclued_path} ...
CXXFLAGS += -Wall ${BASE_INC_PATH} -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -g 
ldlibs=${LDLIBS}

smtp_server:clean
	g++ -o smtp_server smtp_server.c util_socket.c util_pthread_pool.c \
		 ${CXXFLAGS} ${LDLIBS}
make:smtp_server
		
run:make
	./smtp_server	

clean:
	rm -rf *.o smtp_server dns

build_dns:clean
	g++ -o dns util_dns.c ${CXXFLAGS} ${LDLIBS}  -DTEST_DNS_UTIL 

run_dns:build_dns
	./dns -h www.qq.com 

