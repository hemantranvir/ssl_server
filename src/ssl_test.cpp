#include "ssl_test.hpp"

SSLTest::SSLTest()
{
}

SSLTest::~SSLTest()
{
}

bool SSLTest::PushClientServerMsg(const ClientServerMsg msg, std::vector<ClientServerMsg>& msgs)
{
    if (msg.m_client_msg.empty() || msg.m_server_msg.empty()) {
        std::cout << "[SSLTest] Client Msg or Server Msg cannot be empty" << std::endl;
        return false;
    }
    msgs.push_back(msg);
    return true;
}
