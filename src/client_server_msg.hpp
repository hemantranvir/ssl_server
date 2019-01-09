#ifndef CLIENT_SERVER_MSG_HPP__
#define CLIENT_SERVER_MSG_HPP__

#include <string>

enum Condition
{
    kRecv = 1, //Expects string as argument to compare against received fix message
};

struct ClientServerMsg
{
public:
    ClientServerMsg();
    ClientServerMsg(const std::string client_msg_, const Condition condn_, const std::string server_msg_);

    std::string m_client_msg;
    Condition condn;
    std::string m_server_msg;
};

#endif // CLIENT_SERVER_MSG_HPP__

