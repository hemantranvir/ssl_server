#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>
#include "gtest/gtest.h"
#include "ssl_test.hpp"
#include "server.hpp"
#include "client.hpp"
#include "count.hpp"

TEST_F(SSLTest, AES128_SHA_OpenSSLCipherON_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;
    Server server(5001, msgs, counter);

    Client client("./cert/demoCA", "AES128-SHA", 5001, msgs, counter, true);
    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}

TEST_F(SSLTest, AES256_SHA_OpenSSLCipherON_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;
    Server server(5001, msgs, counter);

    Client client("./cert/demoCA", "AES256-SHA", 5001, msgs, counter, true);
    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}
TEST_F(SSLTest, AES128_SHA_OpenSSLCipherOFF_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;
    Server server(5001, msgs, counter);

    Client client("./cert/demoCA", "AES128-SHA", 5001, msgs, counter, false);
    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}

TEST_F(SSLTest, AES256_SHA_OpenSSLCipherOFF_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;
    Server server(5001, msgs, counter);

    Client client("./cert/demoCA", "AES256-SHA", 5001, msgs, counter, false);
    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}

TEST_F(SSLTest, AES128GCM_SHA256_OpenSSLCipherON_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;
    Server server(5001, msgs, counter);

    Client client("./cert/demoCA", "AES128-GCM-SHA256", 5001, msgs, counter, true);
    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}

TEST_F(SSLTest, AES256GCM_SHA384_OpenSSLCipherON_Test)
{
    std::vector<ClientServerMsg> msgs;
    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=9535=A34=149=CAXDemo_tradea_Str52=20181108-10:54:00.33456=CNX98=0108=30141=Y554=Yjfx123410=035",
                                                    kRecv,
                                                    "8=FIX.4.49=8235=A49=CNX34=152=20181108-10:54:00.20756=CAXDemo_tradea_Str98=0108=30141=Y10=215"),
                                    msgs));

    EXPECT_TRUE(PushClientServerMsg(ClientServerMsg("8=FIX.4.49=6435=534=849=CAXDemo_tradea_Str52=20181108-10:54:02.73656=CNX10=149",
                                                    kRecv,
                                                    "8=FIX.4.49=6535=549=CNX34=1252=20181108-10:54:02.29456=CAXDemo_tradea_Str10=192"),
                                    msgs));

    Count counter;

    Server server(5001, msgs, counter);
    Client client("./cert/demoCA", "AES256-GCM-SHA384", 5001, msgs, counter, true);

    EXPECT_TRUE(client.Connect());

    EXPECT_TRUE(counter.Wait(2, 3000));

    server.Join();
    client.Join();

    EXPECT_TRUE(server());
    EXPECT_TRUE(client());
}
