#ifndef COUNT_HPP__
#define COUNT_HPP__

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

class Count
{
public:
    Count();
    explicit Count (int init);
    ~Count();

    bool Wait(int servers, int timeout);
    void Increment(void);
    void Finish(void);

private:
    int count_;
    bool finish_;

    boost::mutex mutex_;
    boost::condition_variable cond_;
};

#endif // COUNT_HPP__
