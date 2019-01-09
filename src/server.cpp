#include "server.hpp"
#include "count.hpp"
#include "ssl_server.hpp"

const int Server::m_buf_size = 2048;

Server::Server(int port, const std::vector<ClientServerMsg>& msgs, Count& count)
    : m_acceptor(m_io_service)
    , m_socket(m_io_service)
    , m_port(port)
    , m_cert_file("./cert/server-cert.pem")
    , m_key_file("./cert/server-privatekey.pem")
    , m_ssl_server(nullptr)
    , m_connected(false)
    , m_recv_buf(m_buf_size, 0)
    , m_msgs(msgs)
    , m_msg_no(0)
    , m_count(count)
    , m_server_status(true)
    , m_running(true)
{
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), m_port);
    m_acceptor.open(endpoint.protocol());
    m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    m_acceptor.bind(endpoint);
    m_acceptor.listen(boost::asio::socket_base::max_connections);
    StartAccept();
    m_thread = boost::thread(boost::bind(&WorkerFunc, this));
}

Server::Server(int port, const std::vector<ClientServerMsg>& msgs, Count& count, const std::string& cert_file, const std::string& key_file)
    : m_acceptor(m_io_service)
    , m_socket(m_io_service)
    , m_port(port)
    , m_cert_file(cert_file)
    , m_key_file(key_file)
    , m_ssl_server(nullptr)
    , m_connected(false)
    , m_recv_buf(m_buf_size, 0)
    , m_msgs(msgs)
    , m_msg_no(0)
    , m_count(count)
    , m_server_status(true)
    , m_running(true)
{
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), m_port);
    m_acceptor.open(endpoint.protocol());
    m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    m_acceptor.bind(endpoint);
    m_acceptor.listen(boost::asio::socket_base::max_connections);
    StartAccept();
    m_thread = boost::thread(boost::bind(&WorkerFunc, this));
}

Server::~Server()
{
    Join();
}

void Server::Join(void)
{
#ifdef DEBUG
    std::cout << "[Server Port: " << m_port << "] Join Called" << " Running Value: " << m_running << std::endl;
#endif
    if (m_running) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Join Called" << std::endl;
#endif
        m_running = false;

        m_acceptor.cancel();
        m_acceptor.close();
        boost::system::error_code ec;
        m_socket.shutdown( boost::asio::ip::tcp::socket::shutdown_both, ec );
        m_socket.close( ec );
        if (ec) {
#ifdef DEBUG
            std::cout << "[Tcp Server Port: " << m_port << "] Error Closing Socket" << std::endl;
#endif
        }
        m_io_service.stop();

        m_thread.join();
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Join Finished" << std::endl;
#endif
    }
}

void Server::WorkerFunc(void* obj)
{
    Server* serv = reinterpret_cast<Server*>(obj);
    serv->WorkerCore();
}

bool Server::operator()()
{
    return m_server_status;
}

void Server::WorkerCore(void)
{
    m_io_service.run();
}

void Server::StartAccept()
{
#ifdef DEBUG
    std::cout << "[Server Port: " << m_port << "] Waiting for Connection..." << std::endl;
#endif
    m_acceptor.async_accept(m_socket, boost::bind(&Server::HandleAccept, this, boost::asio::placeholders::error));
}

void Server::HandleAccept(const boost::system::error_code& error)
{
    if (!error) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Successfully Session Accepted!" << std::endl;
#endif

        StartRead();

        if (!ConnectSSL()) {
#ifdef DEBUG
            std::cout << "[Server] " << "ConnectSSL Failed" << std::endl;
#endif
        }
    }
    else {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Error in Accepting Connection, error: " << error << std::endl;
#endif
    }
}

void Server::StartRead()
{
    boost::asio::async_read(m_socket, boost::asio::buffer(m_recv_buf), boost::asio::transfer_at_least(1),
                            boost::bind(&Server::HandleRead, this,
                                        boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void Server::HandleRead(const boost::system::error_code& error, size_t bytes_transferred)
{
    if (error && error != boost::asio::error::eof && error !=  boost::asio::error::operation_aborted) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Receive Failed: " << error.message() << std::endl;
#endif
        m_server_status = false;
        m_count.Finish();
    }
    else if (error ==  boost::asio::error::operation_aborted) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] Stopping Server Operation" << std::endl;
#endif
    }
    else if (error ==  boost::asio::error::eof) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port << "] EOF, Stopping Server Operation" << std::endl;
#endif
        boost::system::error_code ec;
        m_socket.shutdown( boost::asio::ip::tcp::socket::shutdown_both, ec );
        m_socket.close( ec );
    }
    else {
        std::string recv_msg(m_recv_buf.begin(), m_recv_buf.begin()+bytes_transferred);
        std::fill(m_recv_buf.begin(), m_recv_buf.end(), 0);
        std::string send_msg;
        std::cout << "[HandleRead] bytes_transferred: " << bytes_transferred
                  << " recv_msg[3:4]: " << ((((unsigned int)recv_msg[3] & 0xff) << 8) | ((unsigned int)recv_msg[4] & 0xff))
                  << " recv_msg.size(): " << recv_msg.size() << std::endl;

#ifdef DEBUG
        std::cout << "[Server] " << "Message received in hex" << std::endl;
        for (int i = 0; i < recv_msg.size(); i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)((unsigned char)recv_msg[i]);
            std::cout << " ";
        }
        std::cout << std::endl;
#endif

        int ret = m_ssl_server->DecryptSSL(recv_msg, send_msg);

        if (ret == SSLHandler::kSSLHandShakeInProgress || ret == SSLHandler::kSSLHandShakeDone) {
            if (!send_msg.empty() && !Send(send_msg)) {
#ifdef DEBUG
                std::cout << "[Server] " << "Send failed" << std::endl;
#endif
            }
            StartRead();
            return;
        }
        else if (ret == SSLHandler::kSSLSuccess) {
        }
        else {
#ifdef DEBUG
            std::cout << "[Server] HandleRead Failed" << std::endl;
#endif
            StartRead();
            return;
        }

        const std::string msg_div("8=");
        std::string msg_buf(recv_msg);
        std::vector<std::string> recv_msgs;
        std::string::size_type st_pos = 0;
        std::string::size_type pos = msg_buf.find(msg_div);
        while (pos != std::string::npos) {
            recv_msgs.push_back(msg_buf.substr(st_pos, pos));
            st_pos = pos + 1;
            pos = msg_buf.find(msg_div, st_pos);
        }
        recv_msgs.push_back(msg_buf.substr(st_pos, pos));

        for (auto it = recv_msgs.cbegin(); it != recv_msgs.cend(); it++) {
#ifdef DEBUG
            std::cout << "[Server] " << "Recv Msg after decrypt: " << *it << std::endl;
#endif
            EXPECT_EQ(recv_msgs[0], m_msgs[m_msg_no].m_client_msg) << "[Server] Recevied Msg is not equal to saved msg";

            if (m_msg_no < m_msgs.size()) {
                Send(m_msgs[m_msg_no].m_server_msg);
                m_msg_no++;
                if (m_msg_no == m_msgs.size()) m_count.Increment();
            }
        }

        StartRead();
    }
}

bool Server::Send(const std::string& send_buf)
{
    std::string enc_msg(send_buf);

    if (m_connected) {
        if (m_ssl_server->EncryptSSL(enc_msg) != SSLHandler::kSSLSuccess) return false;
    }

    boost::system::error_code err;
    boost::asio::write(m_socket, boost::asio::buffer(enc_msg), err);
    if (err) {
#ifdef DEBUG
        std::cout << "[Server Port: " << m_port  << "] Send Error: " << err.message() << std::endl;
#endif
        m_server_status = false;
        m_count.Finish();
        return false;
    }
    if (!m_connected && m_ssl_server->IsHandShakeDone()) {
        m_connected = true;
    }

    return true;
}

bool Server::ConnectSSL()
{
    std::string send_msg;
    m_ssl_server = std::unique_ptr<SSLServer>(new SSLServer());

    if (!m_ssl_server->InitSSLServer(m_cert_file, m_key_file)) {
#ifdef DEBUG
        std::cout << "[Server] " << "InitSSLClient failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Server] " << "InitSSLClient successfull" << std::endl;
#endif

    if (!m_ssl_server->KickHandShake(send_msg)) {
#ifdef DEBUG
        std::cout << "[Server] " << "KickHandShake failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Server] " << "KickHandShake successfull" << std::endl;
#endif

    if (!send_msg.empty() && !Send(send_msg)) {
#ifdef DEBUG
        std::cout << "[Server] " << "Send failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Server] " << "Send successfull" << std::endl;
#endif

    return true;
}
