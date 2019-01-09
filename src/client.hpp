#ifndef _CLIENT_HPP__
#define _CLIENT_HPP__

#include <boost/thread.hpp>
#include <string>
#include <boost/asio.hpp>
#include "gtest/gtest.h"
#include "client_server_msg.hpp"

class Count;
class SSLClient;
class SSLCipher;

class Client
{
public:
    Client(int port, const std::vector<ClientServerMsg>& msgs, Count& count, bool openssl_cipher_on);
    Client(const std::string& ssl_cadir, const std::string& ssl_cipher, int port, const std::vector<ClientServerMsg>& msgs, Count& count, bool openssl_cipher_on);
    virtual ~Client(void);

    bool Connect(void);

    void Join(void);

    static void WorkerFunc(void* obj);
    bool operator()();

protected:
    bool Disconnect(void);
    bool ConnectSSL(void);

    bool Send(const std::string& msg);
    bool ReceiveAsync(void);

    void WorkerCore(void);
    void OnReceive(const boost::system::error_code& err, size_t byte_transferred);

    boost::asio::io_service m_io_service;
    boost::asio::ip::tcp::socket m_socket;
    static const int m_buf_size;
    std::vector<char> m_recv_buf;

    boost::thread m_worker;
    boost::mutex m_mutex;
    boost::condition_variable m_cond;

    std::string m_ip;
    int m_port;

    std::string m_ssl_cadir;
    std::string m_ssl_cipher_suite;
    std::unique_ptr<SSLClient> m_ssl_client;
    std::unique_ptr<SSLCipher> m_ssl_cipher;

    bool m_connected;
    std::string m_msg_buf;
    std::vector<ClientServerMsg> m_msgs;
    int m_msg_no;
    Count& m_count;
    bool m_client_status;
    bool m_openssl_cipher_on;
};

#endif // _CLIENT_HPP__
