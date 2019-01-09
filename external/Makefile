BOOST_TBZ = boost_1_65_1.tar.bz2
BOOST_DIR = boost_1_65_1
BOOST_INSTALL_DIR = boost
BOOST_INC_DIR = $(BOOST_INSTALL_DIR)/include/boost

GTEST_TGZ = googletest-release-1.8.0.tar.gz
GTEST_EXTRACT_DIR = googletest-release-1.8.0
GTEST_ARM_INSTALL_DIR = gtest-1.8.0-arm
GTEST_INSTALL_DIR = gtest-1.8.0

OPENSSL_TGZ = openssl-1.1.1.tar.gz
OPENSSL_DIR = openssl-1.1.1
OPENSSL_INSTALL_DIR = openssl
OPENSSL_LIB_DIR = openssl_lib
OPENSSL_EXISTS = $(shell ls $(OPENSSL_INSTALL_DIR)/include/openssl/opensslconf.h)
OPENSSL_LIB_EXISTS = $(shell ls $(OPENSSL_LIB_DIR)/include/openssl/opensslconf.h)

all: boost-build gtest-build openssl-lib-build

boost-build: boost_extract
	$(if $(shell ls $(BOOST_INC_DIR)/asio.hpp), @echo "already built boost.", \
	cd $(BOOST_DIR) && ./bootstrap.sh --prefix=../$(BOOST_INSTALL_DIR) --with-libraries=system,thread,date_time && ./b2 --with-system --with-thread --with-date_time link=static install)

boost_extract:
	$(if $(shell ls $(BOOST_DIR)), , tar jxf $(BOOST_TBZ))

gtest-build: gtest_extract
	$(if $(shell ls $(GTEST_INSTALL_DIR)/lib/libgtest.a), @echo "already built gtest.", \
	mkdir -p $(GTEST_INSTALL_DIR)/build && cd $(GTEST_INSTALL_DIR)/build && cmake ../../$(GTEST_EXTRACT_DIR) -DCMAKE_INSTALL_PREFIX=.. -DBUILD_GMOCK:BOOL=ON -DBUILD_GTEST:BOOL=ON && make install)

gtest_extract:
	$(if $(shell ls $(GTEST_EXTRACT_DIR)), , tar -xzf $(GTEST_TGZ))

openssl-build: openssl_extract
	$(if $(OPENSSL_EXISTS), @echo "already built openssl.", \
	cd $(OPENSSL_DIR) && ./config -maes -mpclmul -msse4.1 no-shared no-asm --prefix=$(PWD)/$(OPENSSL_INSTALL_DIR) --openssldir=$(PWD)/$(OPENSSL_INSTALL_DIR)/ssl && make && make install_sw install_ssldirs) \

openssl-lib-build: openssl-build
	cd $(OPENSSL_DIR) && make clean && ./config --prefix=$(PWD)/$(OPENSSL_LIB_DIR) --openssldir=$(PWD)/$(OPENSSL_LIB_DIR)/ssl && make && make install_sw install_ssldirs

openssl_extract: 
	$(if $(shell ls $(OPENSSL_DIR)), , tar zxf $(OPENSSL_TGZ))
