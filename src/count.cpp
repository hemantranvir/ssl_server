#include "count.hpp"

Count::Count(void)
    : count_(0)
    , finish_(false)
{
}

Count::Count(int init)
    : count_(init)
{

}

Count::~Count(void)
{

}

bool Count::Wait(int servers, int timeout)
{
#ifdef DEBUG
    std::cout << "[Count] wait called" << std::endl;
#endif
    bool ret = true;
    boost::system_time timeout_time(boost::posix_time::microsec_clock::universal_time()
                                   + boost::posix_time::milliseconds(timeout));

    boost::mutex::scoped_lock lock(mutex_);
    while (count_ < servers && !finish_) {
#ifdef DEBUG
        std::cout << "[Count] waiting.." << std::endl;
#endif
        if (!cond_.timed_wait(lock, timeout_time)) {
            std::cout << "[Count] Timed Out, Breaking..." << std::endl;
            return false;
        }
    }

    if (finish_) {
#ifdef DEBUG
        std::cout << "[Count] Finish Called" << std::endl;
#endif
        ret =  false;
    }

    return ret;
}

void Count::Increment(void)
{
    boost::mutex::scoped_lock lock(mutex_);
    ++count_;
#ifdef DEBUG
    std::cout << "[Count] Count Incremented to " << count_ << std::endl;
#endif
    cond_.notify_all();
}

void Count::Finish(void)
{
    boost::mutex::scoped_lock lock(mutex_);
    finish_ = true;
    cond_.notify_all();
}
