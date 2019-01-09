.PHONY: all certdir cert_ca cert_server run_ssl_tests clean 

BOOST_DIR := $(PWD)/../external/boost
GTEST_DIR := $(PWD)/../external/gtest-1.8.0
OPENSSL_DIR := $(PWD)/../external/openssl
OPENSSL_SRC_DIR := $(PWD)/../external/openssl-1.1.1
OPENSSL_BIN_DIR := $(OPENSSL_DIR)/bin
ENV_SET := env PATH=$(OPENSSL_BIN_DIR)
CERT_DIR := ./cert
CERT_CA_DIR := $(CERT_DIR)/demoCA

SERVER_KEY_FILE := server-privatekey.pem
SERVER_CSR_FILE := server-csr.pem
SERVER_CERT_FILE := server-cert.pem

#CLIENT_CIPHER_NAME := AES128-GCM-SHA256

SRCS = count.cpp \
	ssl_client.cpp \
	ssl_cipher.cpp \
	ssl_server.cpp \
	server.cpp \
	client.cpp \
	ssl_test.cpp \
        client_server_msg.cpp \
	connection_test.cpp \
	run_ssl_test.cpp

SRCS_C = ssl_functions.c

OBJS = $(SRCS:.cpp=.o)

OBJS_C = $(SRCS_C:.c=.o)

EXEC = run_ssl_tests

CFLAGS = -g -std=c++11 -I../arbitrage -I../common -DDEBUG
CFLAGS += -I$(BOOST_DIR)/include/
CFLAGS += -I$(GTEST_DIR)/include/
CFLAGS += -I$(OPENSSL_SRC_DIR)/include -I$(OPENSSL_SRC_DIR)

CFLAGS_C = -g -Wall -O0 -maes -mpclmul -msse4.1 -I../arbitrage
CFLAGS_C += -I$(BOOST_DIR)/include/
CFLAGS_C += -I$(OPENSSL_SRC_DIR)/include -I$(OPENSSL_SRC_DIR)

LDFLAGS = -L$(BOOST_DIR)/lib -L$(GTEST_DIR)/lib -L$(OPENSSL_DIR)/lib -lboost_thread -lboost_date_time -lboost_system -lgtest  -lssl -lcrypto -ldl -lpthread

vpath %.cpp ../src
vpath %.c ../src

all: cert_server $(EXEC)

certdir:
	@if [ ! -e ${CERT_CA_DIR} ]; then \
		mkdir -p ${CERT_CA_DIR}; \
	fi

cert_ca: certdir
	@mkdir -p $(CERT_CA_DIR)/certs $(CERT_CA_DIR)/private $(CERT_CA_DIR)/crl $(CERT_CA_DIR)/newcerts
	cd $(CERT_CA_DIR); \
	$(ENV_SET) openssl genrsa -out private/cakey.pem 2048; \
	$(ENV_SET) openssl req -batch -new -key private/cakey.pem -out cacsr.pem -subj /C=JP/ST=Tokyo/O=Company/CN=test; \
	$(ENV_SET) openssl req -x509 -key private/cakey.pem -in cacsr.pem -out cacert.pem -days 3650; \
	echo "01" > serial; \
	echo -n > index.txt; \
	c_rehash .

cert_server: cert_ca
	cd $(CERT_DIR); \
	$(ENV_SET) openssl genrsa -out server-privatekey.pem; \
	$(ENV_SET) openssl req -batch -new -key $(SERVER_KEY_FILE) -out $(SERVER_CSR_FILE) -subj /C=JP/ST=Tokyo/O=Company/CN=test; \
	$(ENV_SET) openssl ca -batch -out $(SERVER_CERT_FILE) -infiles $(SERVER_CSR_FILE); \
	cd ..

$(OBJS_C): $(SRCS_C)
	gcc $(CFLAGS_C) -c $<

$(EXEC): $(OBJS) $(OBJS_C)
	g++ -o $@ $(OBJS_C) $(OBJS) $(CFLAGS_C) $(CFLAGS) $(LDFLAGS)

.cpp.o:
	g++ $(CFLAGS) -c $<

.c.o:
	gcc $(CFLAGS_C) -c $<

clean:
	rm -rf $(CERT_DIR)
	rm -f $(OBJS) $(OBJS_C) *~ $(EXEC)
