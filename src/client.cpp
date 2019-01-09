#include "client.hpp"
#include "count.hpp"
#include "ssl_client.hpp"
#include "ssl_cipher.hpp"

const int Client::m_buf_size = 2048;

Client::Client(int port, const std::vector<ClientServerMsg>& msgs, Count& count, bool openssl_cipher_on)
    : m_socket(m_io_service)
    , m_recv_buf(m_buf_size, 0)
    , m_ip("127.0.0.1")
    , m_port(port)
    , m_ssl_cadir("./cert/demoCA")
    , m_ssl_cipher_suite("AES128-SHA")
    //, m_ssl_cipher_suite("AES256-SHA")
    //, m_ssl_cipher_suite("AES128-SHA256")
    //, m_ssl_cipher_suite("AES256-SHA256")
    //, m_ssl_cipher_suite("AES128-GCM-SHA256")
    //, m_ssl_cipher_suite("AES256-GCM-SHA384")
    , m_ssl_client(nullptr)
    , m_ssl_cipher(nullptr)
    , m_connected(false)
    , m_msgs(msgs)
    , m_msg_no(0)
    , m_count(count)
    , m_client_status(true)
    , m_openssl_cipher_on(openssl_cipher_on)
{
}

Client::Client(const std::string& ssl_cadir, const std::string& ssl_cipher, int port, const std::vector<ClientServerMsg>& msgs, Count& count, bool openssl_cipher_on)
    : m_socket(m_io_service)
    , m_recv_buf(m_buf_size, 0)
    , m_ip("127.0.0.1")
    , m_port(port)
    , m_ssl_cadir(ssl_cadir)
    , m_ssl_cipher_suite(ssl_cipher)
    , m_ssl_client(nullptr)
    , m_ssl_cipher(nullptr)
    , m_connected(false)
    , m_msgs(msgs)
    , m_msg_no(0)
    , m_count(count)
    , m_client_status(true)
    , m_openssl_cipher_on(openssl_cipher_on)
{
}

Client::~Client(void)
{
    Disconnect();
}

bool Client::Connect()
{
    // sync connect
    boost::system::error_code err;
#ifdef DEBUG
    printf("connecting [%s] with port %d\n", m_ip.c_str(), m_port);
#endif
    m_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(m_ip), m_port), err);

    if (err) {
#ifdef DEBUG
        printf("cannot connect [%s] with port %d (err=%s)\n", m_ip.c_str(), m_port, err.message().c_str());
#endif
        return false;
    }
#ifdef DEBUG
    printf("connected [%s] with port %d\n", m_ip.c_str(), m_port);
#endif

    m_connected = true;

    ReceiveAsync();

    // worker thread
    m_worker = boost::thread(boost::bind(&WorkerFunc, this));

    if (!ConnectSSL()){
        return false;
    }

    if (!Send(m_msgs[m_msg_no].m_client_msg)) return false;

    return true;
}

void Client::Join(void)
{
    Disconnect();
}

void Client::WorkerFunc(void* obj)
{
    Client* cp = reinterpret_cast<Client*>(obj);
    cp->WorkerCore();
}

bool Client::operator()()
{
    return m_client_status;
}

bool Client::Disconnect(void)
{
    boost::mutex::scoped_lock lock(m_mutex);
    if (m_worker.joinable()) {
        m_socket.close();
        while (m_connected) {
            m_cond.wait(lock);
        }
        m_worker.join();
    }

    if (m_ssl_client != nullptr) {
        m_ssl_client = nullptr;
    }

    if (m_ssl_cipher != nullptr) {
        m_ssl_cipher = nullptr;
    }

    return true;
}

bool Client::ConnectSSL(void)
{
#ifdef DEBUG
    std::cout << "[Client] " << "ConnectSSL called" << std::endl;
#endif
    // When SSL on, First message is sent.
    std::string send_msg;
    if (m_ssl_cipher_suite == "NoSSL" || m_ssl_cipher_suite == "") {
        return false;
    }

    m_ssl_client = std::unique_ptr<SSLClient>(new SSLClient());

    if (m_ssl_client->InitSSLClient(m_ssl_cadir, m_ssl_cipher_suite) != SSLHandler::kSSLSuccess) {
#ifdef DEBUG
        std::cout << "[Client] " << "InitSSLClient failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Client] " << "InitSSLClient successed" << std::endl;
#endif
    if (!m_ssl_client->KickHandShake(send_msg)) {
#ifdef DEBUG
        std::cout << "[Client] " << "KickHandShake failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Client] " << "KickHandShake successed" << std::endl;
#endif
    if (!Send(send_msg)) {
#ifdef DEBUG
        std::cout << "[Client] " << "Send failed" << std::endl;
#endif
        return false;
    }
#ifdef DEBUG
        std::cout << "[Client] " << "Send successed" << std::endl;
#endif
    if (m_ssl_client->Wait(2000) != SSLHandler::kSSLSuccess) {
#ifdef DEBUG
        std::cout << "[Client]" << "Wait failed" << std::endl;
#endif
        return false;
    }

    std::string iv, key, mac;
    std::vector<unsigned char> master;
    std::vector<unsigned char> rx_iv;
    std::vector<unsigned char> rx_key;
    std::vector<unsigned char> rx_key_exp;
    std::vector<unsigned char> rx_mac;
    std::vector<unsigned char> tx_iv;
    std::vector<unsigned char> tx_key;
    std::vector<unsigned char> tx_mac;

#ifdef DEBUG
    std::cout << "[Client] " << "SSL Connected!" << std::endl;
#endif
    if (!m_ssl_client->GetMasterSecret(master)) {
#ifdef DEBUG
        std::cout << "[Client]" << "GetMasterKey failed" << std::endl;
#endif
        return false;
    }

#ifdef DEBUG
    std::cout << "Master Key: ";
    for(int i = 0; i < master.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +master[i];
    }
    std::cout << std::endl;
#endif

    if (!m_ssl_client->GetReceiveSecrets(rx_iv, rx_key, rx_mac)) {
#ifdef DEBUG
        std::cout << "[Client]" << "GetReceiveSecrets failed" << std::endl;
#endif
        return false;
    }

#ifdef DEBUG
    std::cout << "Rx IV: ";
    for(int i = 0; i < rx_iv.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +rx_iv[i];
    }
    std::cout << std::endl;

    std::cout << "Rx Key: ";
    for(int i = 0; i < rx_key.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +rx_key[i];
    }
    std::cout << std::endl;

    std::cout << "Rx Mac: ";
    for(int i = 0; i < rx_mac.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +rx_mac[i];
    }
    std::cout << std::endl;
    std::cout << std::dec << std::endl;
#endif

    if (!m_ssl_client->GetTransmitSecrets(tx_iv, tx_key, tx_mac)) {
#ifdef DEBUG
        std::cout << "[Client]" << "GetTransmitSecrets failed" << std::endl;
#endif
        return false;
    }

#ifdef DEBUG
    std::cout << "Tx IV: ";
    for(int i = 0; i < tx_iv.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +tx_iv[i];
    }
    std::cout << std::endl;

    std::cout << "Tx Key: ";
    for(int i = 0; i < tx_key.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +tx_key[i];
    }
    std::cout << std::endl;

    std::cout << "Tx Mac: ";
    for(int i = 0; i < tx_mac.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << +tx_mac[i];
    }
    std::cout << std::endl;
    std::cout << std::dec << std::endl;
#endif

    std::string name;
    m_ssl_client->GetCipherName(name);

#ifdef DEBUG
    std::cout << "[Client]" << "Cipher Suite is: " << name << std::endl;
#endif

    if (!m_openssl_cipher_on) {
        m_ssl_cipher = std::unique_ptr<SSLCipher>(new SSLCipher());
        m_ssl_cipher->SetMasterSecret(master);
        m_ssl_cipher->SetReceiveSecrets(rx_iv, rx_key, rx_mac);
        m_ssl_cipher->SetTransmitSecrets(tx_iv, tx_key, tx_mac);
    }

    return true;
}

bool Client::Send(const std::string& msg)
{
    boost::system::error_code err;
    std::string enc_msg(msg);
    std::string enc_msg_copy(msg);

    if (m_ssl_client) {
        int ret = m_ssl_client->EncryptSSL(enc_msg);

        if (ret == SSLHandler::kSSLHandShakeInProgress) {
        } else if (ret == SSLHandler::kSSLSuccess) {
#ifdef DEBUG
            std::cout << "[Client]" << "Encrypted message in hex after EncryptSSL:" << std::endl;
            for (int i = 0; i < enc_msg.size(); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)((unsigned char)enc_msg[i]);
                std::cout << " ";
            }
            std::cout << std::endl;
#endif

            if (m_ssl_cipher) {
                m_ssl_cipher->EncryptMsgAESCBC(enc_msg_copy, enc_msg);
#ifdef DEBUG
                std::cout << "[Client]" << "Encrypted message in hex after EncryptMsgAESCBC:" << std::endl;
                for (int i = 0; i < enc_msg_copy.size(); i++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)((unsigned char)enc_msg_copy[i]);
                    std::cout << " ";
                }
                std::cout << std::endl;
#endif
                EXPECT_EQ(enc_msg, enc_msg_copy) << "[Client] EncryptSSL result and EncryptMsgAESCBC result are not equal!";
                enc_msg = enc_msg_copy;
            }
        } else {
#ifdef DEBUG
            std::cout << "[Client]" << "EncryptSSL failed" << std::endl;
#endif
            return false;
        }
    }

    boost::asio::write(m_socket, boost::asio::buffer(enc_msg), err);

    if (err) {
#ifdef DEBUG
        std::cout << "[Client]" << "send failed" << std::endl;
#endif
        m_count.Finish();
        return false;
    }

    return true;
}

bool Client::ReceiveAsync(void)
{
    // async read
    boost::asio::async_read(m_socket, boost::asio::buffer(m_recv_buf), boost::asio::transfer_at_least(1),
                            boost::bind(&Client::OnReceive, this,
                                        boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
    return true;
}

void Client::WorkerCore(void)
{
    m_io_service.run();
}

void Client::OnReceive(const boost::system::error_code& err, size_t byte_transferred)
{
#ifdef DEBUG
    std::cout << "[Client] " << "OnReceive called" << std::endl;
#endif
    if (err && err != boost::asio::error::eof) {
#ifdef DEBUG
        printf("err: %s:%d : %s, (%d)\n", m_ip.c_str(), m_port, err.category().name(), err.value());
#endif
        boost::mutex::scoped_lock lock(m_mutex);
        m_connected = false;
        m_count.Finish();
        m_cond.notify_all();
        return;
    } else if (err && err == boost::asio::error::eof) {
        boost::mutex::scoped_lock lock(m_mutex);
        m_socket.close();
        m_connected = false;
        m_cond.notify_all();
        return;
    } else if (byte_transferred > 0) {
        std::string recv_msg(m_recv_buf.begin(), m_recv_buf.begin()+byte_transferred);
        std::string recv_msg_copy(recv_msg);
        std::fill(m_recv_buf.begin(), m_recv_buf.end(), 0);
        std::string send_msg;

#ifdef DEBUG
        std::cout << "[Client] " << "len is: " << std::dec << recv_msg.length() << std::endl;
#endif

        if (m_ssl_client) {
            int ret = m_ssl_client->DecryptSSL(recv_msg, send_msg);

            if (ret == SSLHandler::kSSLHandShakeInProgress || ret == SSLHandler::kSSLHandShakeDone) {
                if (!send_msg.empty() && !Send(send_msg)) {
#ifdef DEBUG
                    std::cout << "[Client] " << "Send failed" << std::endl;
#endif
                }
                ReceiveAsync();
                return;
            }
            else if (ret != SSLHandler::kSSLSuccess) {
#ifdef DEBUG
                std::cout << "[Client] DecryptSSL Failed" << std::endl;
#endif
                ReceiveAsync();
                return;
            }
        }

#ifdef DEBUG
        std::cout << "[Client]" << "Received Msg after DecryptSSL: " << recv_msg << std::endl;
#endif

        if (m_ssl_cipher) {
            if (!m_ssl_cipher->DecryptMsgAESCBC(recv_msg_copy)) {
#ifdef DEBUG
                std::cout << "[Client] " << "DecryptMsgAESCBC failed" << std::endl;
#endif
            } else {

#ifdef DEBUG
                std::cout << "[Client]" << "Received Msg after DecryptMsgAESCBC: " << recv_msg_copy << std::endl;
#endif
            }

            EXPECT_EQ(recv_msg, recv_msg_copy) << "[Client] DecryptSSL result and DecryptMsgAESCBC result are not equal!" ;
        }

        EXPECT_EQ(recv_msg, m_msgs[m_msg_no].m_server_msg) << "[Client] Saved msg and received msg are not equal!" ;

        m_msg_no++;
        if (m_msg_no == m_msgs.size()) m_count.Increment();

        if (m_msg_no < m_msgs.size()) {
            Send(m_msgs[m_msg_no].m_client_msg);
        }
    }
    ReceiveAsync();
}
