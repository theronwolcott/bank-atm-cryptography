CC = gcc

ifeq ($(CC),clang)
  STACK_FLAGS = -fno-stack-protector -Wl,-allow_stack_execute
else
  STACK_FLAGS = -fno-stack-protector -z execstack
endif

CFLAGS = ${STACK_FLAGS} -Wall -Iutil -Iatm -Ibank -Irouter -I.

all: bin bin/atm bin/bank bin/router bin/init

bin:
	mkdir -p bin

bin/init: init/init.c
	${CC} ${CFLAGS} init/init.c -o bin/init -lssl -lcrypto

bin/atm : atm/atm-main.c atm/atm.c util/ssl.c
	${CC} ${CFLAGS} atm/atm.c atm/atm-main.c util/ssl.c -o bin/atm -lssl -lcrypto -I/usr/include/openssl

# bin/bank : bank/bank-main.c bank/bank.c
# 	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c -o bin/bank
bin/bank : bank/bank-main.c bank/bank.c util/hash_table.c util/list.c util/list.c util/ssl.c
	${CC} ${CFLAGS} bank/bank.c bank/bank-main.c util/hash_table.c util/ssl.c util/list.c -o bin/bank -lssl -lcrypto -I/usr/include/openssl


bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c util/ssl_example.c util/ssl.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test
	${CC} ${CFLAGS} util/ssl_example.c util/ssl.c -o bin/ssl-example -lssl -lcrypto -I/usr/include/openssl

clean:
	cd bin && rm -f *
