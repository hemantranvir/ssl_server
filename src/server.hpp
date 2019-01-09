#ifndef _SERVER_HPP__
#define _SERVER_HPP__

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>
#include <thread>
#include "boost/bind.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/asio.hpp"
#include "boost/algorithm/string.hpp"
#include "boost/thread.hpp"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/modes.h"
#include "client_server_msg.hpp"
#include "gtest/gtest.h"

class Count;
class SSLServer;

class Server
{
public:
    Server(int port, const std::vector<ClientServerMsg>& msgs, Count& count);
    Server(int port, const std::vector<ClientServerMsg>& msgs, Count& count, const std::string& cert_file, const std::string& key_file);
    ~Server();

    void Join(void);
    static void WorkerFunc(void* obj);

    bool operator()();

private:
    void WorkerCore(void);
    void StartAccept();
    void HandleAccept(const boost::system::error_code& error);
    void StartRead();
    void HandleRead( const boost::system::error_code& error, size_t bytes_transferred);
    bool Send(const std::string& send_buf);

    bool ConnectSSL();

    boost::asio::io_service m_io_service;
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::asio::ip::tcp::socket m_socket;

    boost::thread m_thread;
    boost::mutex m_mutex;
    boost::condition_variable m_cond;

    int m_port;

    std::string m_cert_file;
    std::string m_key_file;
    std::unique_ptr<SSLServer> m_ssl_server;

    bool m_connected;
    static const int m_buf_size;
    std::vector<char> m_recv_buf;
    std::vector<ClientServerMsg> m_msgs;
    int m_msg_no;
    Count& m_count;
    bool m_server_status;
    bool m_running;
};

#endif // _SERVER_HPP__

