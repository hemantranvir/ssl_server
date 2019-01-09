#include "client_server_msg.hpp"
#include <sstream>
#include <iomanip>

ClientServerMsg::ClientServerMsg()
    : m_client_msg("")
    , condn(kRecv)
    , m_server_msg("")
{
}

ClientServerMsg::ClientServerMsg(const std::string client_msg_, const Condition condn_, const std::string server_msg_)
    : m_client_msg(client_msg_)
    , condn(condn_)
    , m_server_msg(server_msg_)
{
}

