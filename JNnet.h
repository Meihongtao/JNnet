#pragma once

#include <algorithm>
#include <string>
#include <string.h>
#include <vector>
#include <functional>
#include <memory>
#include <set>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <assert.h>
#include <queue>
#include <iostream>
#include <thread>
#include <condition_variable>
#include <semaphore.h>

#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

class Log{
public:
    void static INFO(std::string str){
    std::cout << __LINE__ << '\t' << __FUNCTION__ << '\t' << str << std::endl;
    }
};




class noncopyable
{
public:
    noncopyable(const noncopyable &) = delete;
    noncopyable &operator=(const noncopyable &) = delete;
    // void operator=(const noncopyable &) = delete;    // muduo将返回值变为void 这其实无可厚非
protected:
    noncopyable() = default;
    ~noncopyable() = default;
};

// 网络库底层的缓冲区类型定义
class Buffer
{
public:
    
    static const size_t kCheapPrepend = 8;
    static const size_t kInitialSize = 1024;

    explicit Buffer(size_t initalSize = kInitialSize)
        : buffer_(kCheapPrepend + initalSize)
        , reader_index_(kCheapPrepend)
        , writer_index_(kCheapPrepend)
    {
    }

    const std::string get_content()const { std::string result(peek(), readable_bytes()); return result;}

    size_t readable_bytes() const { return writer_index_ - reader_index_; }
    size_t writable_bytes() const { return buffer_.size() - writer_index_; }
    size_t prependable_bytes() const { return reader_index_; }

    // 返回缓冲区中可读数据的起始地址
    const char *peek() const { return begin() + reader_index_; }
    void retrieve(size_t len)
    {
        if (len < readable_bytes())
        {
            reader_index_ += len; // 说明应用只读取了可读缓冲区数据的一部分，就是len长度 还剩下readerIndex+=len到writerIndex_的数据未读
        }
        else // len == readableBytes()
        {
            retrieve_all();
        }
    }

    void retrieve_until(const char* end)
    {
        assert(peek() <= end);
        assert(end <= begin_write());
        retrieve(end - peek());
    }


    void retrieve_all()
    {
        reader_index_ = kCheapPrepend;
        writer_index_ = kCheapPrepend;
    }

    // 把onMessage函数上报的Buffer数据 转成string类型的数据返回
    std::string retrieve_all_asstring() { return retrieve_asstring(readable_bytes()); }
    std::string retrieve_asstring(size_t len)
    {
        std::string result(peek(), len);
        retrieve(len); // 上面一句把缓冲区中可读的数据已经读取出来 这里肯定要对缓冲区进行复位操作
        return result;
    }

    // buffer_.size - writerIndex_
    void ensure_writable_bytes(size_t len)
    {
        if (writable_bytes() < len)
        {
            make_space(len); // 扩容
        }
    }

    void append(const std::string data){
        ensure_writable_bytes(data.size());
        std::copy(data.begin(),data.end(),begin_write());
        writer_index_ += data.size();
    }

    // 把[data, data+len]内存上的数据添加到writable缓冲区当中
    void append(const char *data, size_t len)
    {
        ensure_writable_bytes(len);
        std::copy(data, data+len, begin_write());
        writer_index_ += len;
    }

    const char* find_CRLF() const
    {
        // FIXME: replace with memmem()?
        const char* crlf = std::search(peek(), begin_write(), kCRLF, kCRLF+2);
        return crlf == begin_write() ? NULL : crlf;
    }

    char *begin_write() { return begin() + writer_index_; }
    const char *begin_write() const { return begin() + writer_index_; }

    // 从fd上读取数据
    ssize_t read_fd(int fd, int *saveErrno){
        char extra_buf[65536] = {0};
        struct iovec vec[2];
        const ssize_t writable = writable_bytes();

        vec[0].iov_base = begin()+writer_index_;
        vec[0].iov_len = writable;

        vec[1].iov_base = extra_buf;
        vec[1].iov_len = sizeof(extra_buf);

        const int iovcnt = (writable < sizeof(extra_buf)) ? 2 : 1;
        const ssize_t n = ::readv(fd, vec, iovcnt);
        if (n < 0)
        {
            *saveErrno = errno;
        }
        else if (n <= writable) // Buffer的可写缓冲区已经够存储读出来的数据了
        {
            writer_index_ += n;
        }
        else // extrabuf里面也写入了n-writable长度的数据
        {
            writer_index_ = buffer_.size();
            append(extra_buf, n - writable); // 对buffer_扩容 并将extrabuf存储的另一部分数据追加至buffer_
        }
        return n;

    };
    // 通过fd发送数据
    ssize_t write_fd(int fd, int *saveErrno){
        ssize_t n = ::write(fd, peek(), readable_bytes());
        if (n < 0)
        {
            *saveErrno = errno;
        }
        return n;
    };

private:
    // vector底层数组首元素的地址 也就是数组的起始地址
    char *begin() { return &*buffer_.begin(); }
    const char *begin() const { return &*buffer_.begin(); }


    void make_space(size_t len)
    {
        /**
         * | kCheapPrepend |xxx| reader | writer |                     // xxx标示reader中已读的部分
         * | kCheapPrepend | reader ｜          len          |
         **/
        if (writable_bytes() + prependable_bytes() < len + kCheapPrepend) // 也就是说 len > xxx + writer的部分
        {
            buffer_.resize(writer_index_ + len);
        }
        else // 这里说明 len <= xxx + writer 把reader搬到从xxx开始 使得xxx后面是一段连续空间
        {
            size_t readable = readable_bytes(); // readable = reader的长度
            std::copy(begin() + reader_index_,
                      begin() + writer_index_,  // 把这一部分数据拷贝到begin+kCheapPrepend起始处
                      begin() + kCheapPrepend);
            reader_index_ = kCheapPrepend;
            writer_index_ = reader_index_ + readable;
        }
    }

    std::vector<char> buffer_;
    size_t reader_index_;
    size_t writer_index_;
    static const char kCRLF[];
};

class InetAddress
{
public:
    explicit InetAddress(uint16_t port = 0, std::string ip = "127.0.0.1");
    explicit InetAddress(const sockaddr_in &addr)
        : addr_(addr)
    {
    }

    std::string to_ip() const;
    std::string to_ipport() const;
    uint16_t to_port() const;

    sockaddr_in get_addr(){return addr_;}

    const sockaddr_in *get_addr() const { return &addr_; }
    void set_addr(const sockaddr_in &addr) { addr_ = addr; }

private:
    sockaddr_in addr_;
};

class Socket : noncopyable{
public:

    Socket():fd_(-1){
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    };

    Socket(int fd):fd_(fd){}
    ~Socket(){
        assert(fd_!=-1);
        close(fd_);
    }
    int fd() const {return fd_;}
    void set_nonblocking(){
        fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL) | O_NONBLOCK);
    }
    void bind_address(const InetAddress &local_addr){
        bind(fd_,(sockaddr *)local_addr.get_addr(),sizeof(sockaddr_in));
    }
    void listen(){
        ::listen(fd_,1024);
    }

    void connect(InetAddress *addr){ 
        struct sockaddr_in addr_ = addr->get_addr();
        int ret = ::connect(fd_, (sockaddr*)&addr_, sizeof(addr));
        std::cout << __LINE__ << " " << addr->to_ipport() <<" " << ret << std::endl;
        
    }
    
    void set_reuse_port(bool on){
        int optval = on ? 1 : 0;
        setsockopt(fd_,SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    }

    void set_reuse_addr(bool on){
        int optval = on ? 1 : 0;
        setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); // TCP_NODELAY包含头文件 <netinet/tcp.h>
    }

    void shutdown_write(){
        if (::shutdown(fd_, SHUT_WR) < 0)
        {
            // LOG_ERROR("shutdownWrite error");
        }
    }
    
    int accept(InetAddress *client_addr){
        sockaddr_in addr;
        socklen_t len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        // fixed : int connfd = ::accept(sockfd_, (sockaddr *)&addr, &len);
        int connfd = ::accept4(fd_, (sockaddr *)&addr, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (connfd >= 0)
        {
            client_addr->set_addr(addr);
        }
        return connfd;
    }

private:
    int fd_;
};

class EventLoop;

class Channel : noncopyable{

public:
    using callback_func = std::function<void()>;

    Channel(EventLoop *loop, int fd);

    ~Channel();

    int fd(){return fd_;}
    int events() { return events_;}

    void handle_event();
    void update();

    void enable_read(){ events_ |= (EPOLLIN | EPOLLPRI); update();}
    void disable_read(){ events_ &= ~(EPOLLIN | EPOLLPRI); update();}
    void enable_write(){ events_ &= ~EPOLLOUT; update();}
    void disable_write(){ events_ |= EPOLLOUT; update();}
    void disable_all(){ events_ = 0; update();}

    bool is_noevents() const { return events_ == 0; }
    bool is_writing() const { return events_ & EPOLLOUT; }
    bool is_reading() const { return events_ & (EPOLLIN | EPOLLPRI); }


    void set_ret_events(int ev){ ret_events_ = ev;}

    void set_read_cb(const callback_func cb){ read_cb_ = cb;}
    void set_write_cb(const callback_func cb){write_cb_ = cb;}
    void set_close_cb(const callback_func cb){close_cb_ = cb;}
    void set_error_cb(const callback_func cb){error_cb_ = cb;}

    void remove();
    int mark(){return mark_;}
    void set_mark(int mk){mark_ = mk;}
    

private:

    callback_func read_cb_;
    callback_func write_cb_;
    callback_func close_cb_;
    callback_func error_cb_;
    Socket * sock_;
    EventLoop * loop_;
    int fd_;
    int events_;
    int ret_events_;
    int mark_;
    
};

class Poller{
public:
    const int kNew = -1;    // 某个channel还没添加至Poller          // channel的成员index_初始化为-1
    const int kAdded = 1;   // 某个channel已经添加至Poller
    const int kDeleted = 2; // 某个channel已经从Poller删除
    using channel_vector = std::vector<Channel *>;
    using event_vector = std::vector<epoll_event>;
    
    Poller(EventLoop *loop);
    ~Poller();
    channel_vector poll(int timeMS);
    void update_channel(Channel *ch);
    void remove_channel(Channel *ch);
    void update(int opt,Channel *ch);
    
private:
    EventLoop * loop_;
    std::unordered_map<int,Channel*> channel_maps_;
    event_vector events_;
    channel_vector active_channels;
    int epoll_fd_;

};

class Thread : noncopyable{
public:
    using thread_func = std::function<void()>;
    explicit Thread(thread_func func,const std::string &name = std::string())
        :started_(false)
        ,joined_(false)
        ,name_(name)
        ,tid_(0)
        ,func_(std::move(func))
        
    {
            set_default_name();
    };

    ~Thread(){
        if(started_ && !joined_){
            thread_->detach();
        }
    };

    void start(){
        started_ = true;
        sem_t sem;
        sem_init(&sem,false,0);
        thread_ = std::shared_ptr<std::thread>(new std::thread([&](){
            tid_ = static_cast<pid_t>(::syscall(SYS_gettid));
            sem_post(&sem);
            func_();
        }));

        sem_wait(&sem);
    };
    void join(){
        joined_ = true;
        thread_->join();
    };
    bool started() { return started_; }
    pid_t tid() const { return tid_; }
    const std::string &name() { return name_; }
    static int numCreated() { return num_created_; }

private:
    void set_default_name(){
        num_created_.fetch_add(1);
        int num = num_created_.load();
        if (name_.empty())
        {
            char buf[32] = {0};
            snprintf(buf, sizeof buf, "Thread%d", num);
            name_ = buf;
        }
    };

    bool started_;
    bool joined_;
    std::string name_;
    std::shared_ptr<std::thread> thread_;
    pid_t tid_;
    thread_func func_;
    static std::atomic<int> num_created_;
};

class Timer;
class TimerQueue;
class TimeStamp;

class EventLoop{
public:
    using channel_vector = std::vector<Channel *>;
    using func = std::function<void()>;
    EventLoop();
    ~EventLoop();

    void run_at(TimeStamp time,func cb);

    void run_after(double delay, func cb);

    void run_every(double interval, func cb);

    void cancel(Timer *t);

    void run_in_loop(func func);
    void loop();
    bool is_in_loop_thread(){ return thread_id_== static_cast<pid_t>(::syscall(SYS_gettid));};
    void update_channel(Channel *ch);
    void remove_channel(Channel *ch);
    void add_in_loop(std::function<void()> job);
    void do_append_jobs();
    void wakeup();
    void handle_read();

    void quit();


private:
    channel_vector active_channels_;
    std::unique_ptr<Poller> poller_;
    std::mutex mtx_;
    std::vector<std::function<void()>> jobs_;
    // bool 
    bool quit_;
    int wake_fd_;
    std::unique_ptr<Channel> wake_channel_;
    std::unique_ptr<TimerQueue> timer_queue_;
    std::atomic_bool calling_pending_func_;
    bool looping_;
    const pid_t thread_id_;
    
    

};

class EventLoopThread : noncopyable{
public:
    using thread_init_cb = std::function<void(EventLoop *)>;
    EventLoopThread(const thread_init_cb &cb = thread_init_cb(),const std::string &name = std::string());
    ~EventLoopThread();

    EventLoop * start_loop();

private:
    void thread_func();

    EventLoop *loop_;
    bool exiting_;
    Thread thread_;
    std::mutex mutex_;             // 互斥锁
    std::condition_variable cond_; // 条件变量
    thread_init_cb callback_;
};

class EventLoopThreadPool : noncopyable
{
public:
    using thread_init_cb = std::function<void(EventLoop *)>;

    EventLoopThreadPool(EventLoop *baseLoop, const std::string &nameArg);
    ~EventLoopThreadPool();

    void setThreadNum(int numThreads) { num_threads_ = numThreads; }

    void start(const thread_init_cb &cb = thread_init_cb());

    // 如果工作在多线程中，baseLoop_(mainLoop)会默认以轮询的方式分配Channel给subLoop
    EventLoop *get_next_loop();

    std::vector<EventLoop *> get_all_loops();

    bool started() const { return started_; }
    const std::string name() const { return name_; }

private:
    EventLoop *base_Loop_; // 用户使用muduo创建的loop 如果线程数为1 那直接使用用户创建的loop 否则创建多EventLoop
    std::string name_;
    bool started_;
    int num_threads_;
    int next_; // 轮询的下标
    std::vector<std::unique_ptr<EventLoopThread>> threads_;
    std::vector<EventLoop *> loops_;
};

class Acceptor : noncopyable{
public:

    Acceptor(EventLoop *loop, const InetAddress &addr,bool reuse_port);
    ~Acceptor();

    void set_new_connetion_cb(const std::function<void(int sockfd, const InetAddress &)> cb){
        new_connection_cb_ = cb;
    }

    void listen();
private:
    std::function<void(int fd_,const InetAddress &addr)> new_connection_cb_;
    void handle_read();
    EventLoop * loop_;
    Socket accept_socket_;
    Channel accept_channel_;
    bool is_listenning_;
};

class TcpConnection : noncopyable, public std::enable_shared_from_this<TcpConnection>{
public:
    using tcp_connection_ptr = std::shared_ptr<TcpConnection>;
    using connection_cb = std::function<void(const tcp_connection_ptr &)>;
    using close_cb = std::function<void(const tcp_connection_ptr &)>;
    using write_complete_cb = std::function<void(const tcp_connection_ptr &)>;
    // using HighWaterMarkCallback = std::function<void(const TcpConnectionPtr &, size_t)>;
    using message_cb = std::function<void(const tcp_connection_ptr &,
                                            Buffer *buf)>;
    TcpConnection(EventLoop *loop,int fd_,const std::string &name ,const InetAddress & local_addr,const InetAddress & client_addr);
    ~TcpConnection();

    bool connected() const { return state_ == kConnected; }

    EventLoop *get_loop() const { return loop_; }

    void set_connection_cb(const connection_cb &cb){ connection_cb_ = cb;}

    void set_close_cb(const close_cb &cb){close_cb_ = cb;}

    void set_write_complete_cb(const write_complete_cb &cb){write_complete_cb_ = cb;}

    void set_message_cb(const message_cb & cb){message_cb_ = cb;}

    void send(const std::string &buf);

    

    void connection_established();

    void connection_destroyed();

    void shutdown();

   

    const int get_fd() const {return channel_->fd();};

    InetAddress get_client_addr(){return client_addr_;}

    const std::string &name() const { return name_; }
    const InetAddress &localAddress() const { return local_addr_; }
    const InetAddress &peerAddress() const { return client_addr_; }

private:
    enum StateE
        {
            kDisconnected, // 已经断开连接
            kConnecting,   // 正在连接
            kConnected,    // 已连接
            kDisconnecting // 正在断开连接
        };

    void set_state(StateE state) { state_ = state; }

    void handleRead();
    void handleWrite();
    void handleClose();
    void handleError();

    void send_in_loop(const void *data,size_t len);
    
    void shutdown_in_loop();


    Buffer read_bf_;
    Buffer write_bf_;

    InetAddress local_addr_;
    InetAddress client_addr_;

    EventLoop * loop_;
    std::string name_;
    std::atomic_int state_;

    std::unique_ptr<Channel> channel_;
    std::unique_ptr<Socket> socket_;

    connection_cb connection_cb_;       // 有新连接时的回调
    message_cb message_cb_;             // 有读写消息时的回调
    write_complete_cb write_complete_cb_; // 消息发送完成以后的回调
    // HighWaterMarkCallback highWaterMarkCallback_;
    close_cb close_cb_ ;

};

using thread_init_cb = std::function<void(EventLoop *)>;
using tcp_connection_ptr = std::shared_ptr<TcpConnection>;
using connection_cb = std::function<void(const tcp_connection_ptr &)>;
using close_cb = std::function<void(const tcp_connection_ptr &)>;
using write_complete_cb = std::function<void(const tcp_connection_ptr &)>;

class TcpServer{
public:
    
    // using HighWaterMarkCallback = std::function<void(const TcpConnectionPtr &, size_t)>;
    using message_cb = std::function<void(const tcp_connection_ptr &,
                                            Buffer *buf)>;
    TcpServer(EventLoop *loop,InetAddress &addr);
    ~TcpServer();
    
    EventLoop * const get_loop() const{return loop_;}

    void set_connetion_cb(connection_cb func){
        connection_cb_ = func;
    }

    void set_thread_init_cb(thread_init_cb cb){
        thread_init_cb_ = cb;
    }

    void set_thread_nums(int num){}

    void set_message_cb(message_cb func){
        message_cb_ = func;
    }

    void start();

private:
    void new_connection(int sockfd, const InetAddress &peerAddr);
    void remove_connection(const tcp_connection_ptr &conn);
    void remove_connection_in_loop(const tcp_connection_ptr &conn);
    int next_conn_id_;
    EventLoop * loop_;

    Acceptor * acceptor_;

    std::shared_ptr<EventLoopThreadPool> thread_pool_;
    thread_init_cb thread_init_cb_;
    connection_cb connection_cb_;
    message_cb message_cb_;
    write_complete_cb write_complete_cb_;

    std::unordered_map<std::string, tcp_connection_ptr> connection_maps_;
};

class TimeStamp{
public:
    TimeStamp():micro_seconds_since_epoch_(0){};
    explicit TimeStamp(int64_t ms):micro_seconds_since_epoch_(ms){};
    static TimeStamp now(){  
        struct timeval tv;
        gettimeofday(&tv, NULL);
        int64_t seconds = tv.tv_sec;
        return TimeStamp(seconds * kmicro_seconds_per_second + tv.tv_usec);
     };
    std::string to_string() const{
        char buf[64] = {0};
        time_t seconds = static_cast<time_t>(micro_seconds_since_epoch_ / kmicro_seconds_per_second);
        struct tm tm_time;
        gmtime_r(&seconds, &tm_time);

        if (true)
        {
            int microseconds = static_cast<int>(micro_seconds_since_epoch_ % kmicro_seconds_per_second);
            snprintf(buf, sizeof(buf), "%4d%02d%02d %02d:%02d:%02d.%06d",
                    tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
                    tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec,
                    microseconds);
        }
        return buf;
    };

    static const int kmicro_seconds_per_second = 1000*1000;

    int64_t get_micro_seconds() const {return micro_seconds_since_epoch_;}

    bool operator <(const TimeStamp &b)const { return this->get_micro_seconds() < b.get_micro_seconds();}
    bool operator >(const TimeStamp &b)const { return this->get_micro_seconds() > b.get_micro_seconds();}
    bool operator ==(const TimeStamp &b)const { return this->get_micro_seconds() == b.get_micro_seconds();}

private:
    int64_t micro_seconds_since_epoch_;
};

class Timer{
public:
    static std::atomic_llong num_created_;
    using time_cb = std::function<void()>;
    Timer(time_cb cb,TimeStamp when,double internal)
    :cb_(cb),
    expiration_(when)
    ,interval_(internal)
    ,repeat_(internal > 0.0)
    ,id_(num_created_.fetch_add(1))
    {
    };

    void run() const {
        if(cb_){
            cb_();
        }
        else{
            // std::cout << "Timer cb is not exist !\n";
        }
    }

    void restart(TimeStamp now)
    {
        if (repeat_)
        {
            expiration_ = TimeStamp(now.get_micro_seconds()+interval_*TimeStamp::kmicro_seconds_per_second);
        }
        else
        {
            expiration_ = TimeStamp();
        }
    }

    TimeStamp get_expiration() const{ return expiration_;}

    bool is_repeat() const { return repeat_;};

    static int64_t num_created() { return num_created_.load(); }

    int64_t get_id() const { return id_; }

private:
    const time_cb cb_;
    TimeStamp expiration_;
    const double interval_;
    const bool repeat_;
    const int64_t id_;
    
};


class TimerQueue{
public:
    using Entry = std::pair<TimeStamp,Timer *>;
    using ActiveTimer = std::pair<Timer *,int64_t>;
    using TimerList = std::set<Entry>;
    using ActiveTimerSet = std::set<std::pair<Timer *,int64_t>>;

    TimerQueue(EventLoop *loop)
    :loop_(loop)
    ,time_fd_(timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK | TFD_CLOEXEC))
    ,time_channel_(loop_,time_fd_)
    ,timers_()
    {
        time_channel_.set_read_cb(std::bind(&TimerQueue::handle_read,this));
        time_channel_.enable_read();
    }

    ~TimerQueue(){
        time_channel_.disable_all();
        time_channel_.remove();
        close(time_fd_);
        for (const std::pair<TimeStamp,Timer *>& timer : timers_)
        {
            delete timer.second;
        }
    }

    void add_timer(std::function<void()> cb,TimeStamp when,double interval){
        Timer * timer = new Timer(cb,when,interval);
        loop_->run_in_loop(std::bind(&TimerQueue::add_timer_in_loop,this,timer));
    }

    void cancel(Timer *timer){
        loop_->run_in_loop(std::bind(&TimerQueue::cancel_in_loop, this, timer));
    }

    
private:
    void reset_time_fd(int time_fd,TimeStamp expiration){
        struct itimerspec newValue;
        struct itimerspec oldValue;
        memset(&newValue,0, sizeof(newValue));
        memset(&oldValue,0, sizeof(oldValue));
        newValue.it_value = how_much_time_from_now(expiration);
        int ret = ::timerfd_settime(time_fd, 0, &newValue, &oldValue);
    }

    timespec how_much_time_from_now(TimeStamp when){
        int64_t microseconds = when.get_micro_seconds()
                        - TimeStamp::now().get_micro_seconds();
        if (microseconds < 100)
        {
            microseconds = 100;
        }
        struct timespec ts;
        ts.tv_sec = static_cast<time_t>(
            microseconds / TimeStamp::kmicro_seconds_per_second);
        ts.tv_nsec = static_cast<long>(
            (microseconds % TimeStamp::kmicro_seconds_per_second) * 1000);
        return ts;
    }

    void add_timer_in_loop(Timer * timer){
        if(loop_->is_in_loop_thread()){
            bool earliest_changed = insert(timer);
            if (earliest_changed)
            {
                reset_time_fd(time_fd_, timer->get_expiration());
            }
        }
    }

    bool insert(Timer * timer){
        assert(timers_.size() == active_timers_.size());
        bool earliest_changed = false;
        TimeStamp when = timer->get_expiration();
        TimerList::iterator it = timers_.begin();
        if (it == timers_.end() || when < it->first)
        {
            earliest_changed = true;
        }

        {
            std::pair<TimerList::iterator, bool> result = timers_.insert(Entry(when, timer));
            assert(result.second); 
            (void)result;
        }

        {
            std::pair<ActiveTimerSet::iterator, bool> result = active_timers_.insert(ActiveTimer(timer, timer->get_id()));
            assert(result.second); (void)result;
        }
        assert(timers_.size() == active_timers_.size());
        return earliest_changed;
    }

    void cancel_in_loop(Timer *timer){
        assert(timers_.size() == active_timers_.size());
        ActiveTimer timer_(timer, timer->get_id());
        ActiveTimerSet::iterator it = active_timers_.find(timer_);
        if (it != active_timers_.end())
        {
            size_t n = timers_.erase(Entry(it->first->get_expiration(), it->first));
            assert(n == 1); (void)n;
            delete it->first; // FIXME: no delete please
            active_timers_.erase(it);
        }
        else if (calling_expired_timers_)
        {
            canceling_timers_.insert(timer_);
        }
        assert(timers_.size() == active_timers_.size());
    };

    std::vector<Entry> get_expired(TimeStamp now){
        // Log::INFO(now.to_string());
        // Log::INFO(timers_.begin()->first.to_string());
        assert(timers_.size() == active_timers_.size());
        std::vector<Entry> expired;
        Entry sentry(now, reinterpret_cast<Timer*>(UINTPTR_MAX));
        TimerList::iterator end = timers_.lower_bound(sentry);
        assert(end == timers_.end() || now < end->first);
        // 移除原始 vector 中满足条件的元素
        std::copy(timers_.begin(), end, std::back_inserter(expired));
        timers_.erase(timers_.begin(), end);

        Log::INFO(std::to_string(expired.size()));

        for (const Entry& it : expired)
        {
            ActiveTimer timer(it.second, it.second->get_id());
            size_t n = active_timers_.erase(timer);
            assert(n == 1); (void)n;
        }
        
        assert(timers_.size() == active_timers_.size());
        

        
       
        return expired;
    }

    void reset(const std::vector<Entry>& expired, TimeStamp now){
        TimeStamp nextExpire;

        for (const Entry& it : expired)
        {
            ActiveTimer timer(it.second, it.second->get_id());
            // std::cout << __LINE__ << "\t" << __FUNCTION__ << "\t" << it.second->is_repeat();
            if (it.second->is_repeat()
                && canceling_timers_.find(timer) == canceling_timers_.end())
            {
            it.second->restart(now);
            insert(it.second);
            }
            else
            {
            // FIXME move to a free list
            delete it.second; // FIXME: no delete please
            }
        }
        if (!timers_.empty())
        {
            nextExpire = timers_.begin()->second->get_expiration();
        }
        if (nextExpire.get_micro_seconds() > 0)
        {
            reset_time_fd(time_fd_, nextExpire);
        }
    };

    void handle_read(){
        TimeStamp now(TimeStamp::now());
        // 读取fd
        uint64_t howmany;
        ssize_t n = read(time_fd_, &howmany, sizeof(howmany));

        std::vector<Entry> expired = get_expired(now);

        calling_expired_timers_ = true;
        canceling_timers_.clear();
        // safe to callback outside critical section
        for (const Entry& it : expired)
        {
            it.second->run();
        }
        calling_expired_timers_ = false;

        reset(expired, now);
    }

    EventLoop * loop_;
    const int time_fd_;

    Channel time_channel_;
    TimerList timers_;

    // for cancel()
    ActiveTimerSet active_timers_;
    bool calling_expired_timers_; /* atomic */
    ActiveTimerSet canceling_timers_;


};