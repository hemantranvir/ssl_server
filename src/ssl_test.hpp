#ifndef SSL_TEST_HPP__
#define SSL_TEST_HPP__

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>
#include <thread>
#include "gtest/gtest.h"
#include "client_server_msg.hpp"

class SSLTest : public ::testing::Test
{
public:
    SSLTest();
    ~SSLTest();
protected:
    bool PushClientServerMsg(const ClientServerMsg msg, std::vector<ClientServerMsg>& msgs);

private:
};

#endif // SSL_TEST_HPP__
