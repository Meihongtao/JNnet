#include "JNnet.h"
#include <iostream>

const char Buffer::kCRLF[] = "\r\n";

std::atomic_llong Timer::num_created_(0);


std::atomic<int> Thread::num_created_(0);

// InetAddress
InetAddress::InetAddress(uint16_t port, std::string ip)
{
    ::memset(&addr_, 0, sizeof(addr_));
    addr_.sin_family = AF_INET;
    addr_.sin_port = ::htons(port); // 本地字节序转为网络字节序
    addr_.sin_addr.s_addr = ::inet_addr(ip.c_str());
}

std::string InetAddress::to_ip() const
{
    // addr_
    char buf[64] = {0};
    ::inet_ntop(AF_INET, &addr_.sin_addr, buf, sizeof buf);
    return buf;
}

std::string InetAddress::to_ipport() const
{
    // ip:port
    char buf[64] = {0};
    ::inet_ntop(AF_INET, &addr_.sin_addr, buf, sizeof buf);
    size_t end = ::strlen(buf);
    uint16_t port = ::ntohs(addr_.sin_port);
    sprintf(buf+end, ":%u", port);
    return buf;
}

uint16_t InetAddress::to_port() const
{
    return ::ntohs(addr_.sin_port);
}

// Channel 
Channel::Channel(EventLoop *loop, int fd):loop_(loop),fd_(fd),mark_(-1),events_(0),ret_events_(0){
    // sock_ = new Socket(fd);
    // sock_->set_nonblocking(); 
};

Channel::~Channel(){
    std::cout << __LINE__ <<" "<< this->fd() << " is deleted" << std::endl; 
};

void Channel::update(){
    loop_->update_channel(this);
}

void Channel::handle_event(){
    if((ret_events_ & EPOLLHUP) && !(ret_events_ & EPOLLIN)){
        if(close_cb_){
            close_cb_();
        }
    }
    if(ret_events_ & (EPOLLIN | EPOLLPRI)){
        if(read_cb_){
            read_cb_();
        }
    }
    if(ret_events_ & EPOLLOUT){
        if(write_cb_){
            write_cb_();
        }
    }
    if (ret_events_ & EPOLLERR)
    {
        if (error_cb_)
        {
            error_cb_();
        }
    }
}

void Channel::remove(){
    loop_->remove_channel(this);
}

// Poller 
Poller::Poller(EventLoop * loop):loop_(loop),events_(64){

    
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    std::cout << __LINE__ << "epollfd is:" << epoll_fd_ << std::endl;
}

Poller::~Poller(){
    close(epoll_fd_);
    channel_maps_.clear();
}

std::vector<Channel *> Poller::poll(int timeMs){
    int num_events = epoll_wait(epoll_fd_,&*events_.begin(),static_cast<int>(events_.size()),timeMs);
    int errno_ = errno;
    active_channels.clear();
    if(num_events > 0){
        for(int i=0;i<num_events;i++){
            Channel * ch = (Channel*)(events_[i].data.ptr);
            // assert(ch !=nullptr);
            ch->set_ret_events(events_[i].events);
            active_channels.emplace_back(ch);
        }
        if (num_events == events_.size()) // 扩容操作
        {
            events_.resize(events_.size() * 2);
        }
    }
    else if(num_events == 0){
        // timeout !
    }
    else {
        if(errno_ != EINTR){
            // 
            errno = errno_;
        }
    }
    
    return active_channels;
}

void Poller::update(int opt,Channel*ch){
    struct epoll_event ev {};
    memset(&ev,'\0',sizeof(ev));
    assert(ch != nullptr);

    ev.data.ptr = ch;
    ev.events = ch->events();

    // std::cout << "update fd is " << ch->fd() << " " << opt << std::endl;
    // std::cout << ch <<" epoll fd is:" << epoll_fd_<< std::endl;

    // Channel *ch2 = (Channel*)(ev.data.ptr);

    // assert(ch2 != nullptr);

    // std::cout << ch2->mark() << std::endl;
    if (::epoll_ctl(epoll_fd_, opt, ch->fd(), &ev) < 0)
    {
        
        if (opt == EPOLL_CTL_DEL)
        {
            // LOG_ERROR("epoll_ctl del error:%d\n", errno);
        }
        else
        {
            // LOG_FATAL("epoll_ctl add/mod error:%d\n", errno);
        }
    }
}

void Poller::remove_channel(Channel *ch){
    int fd = ch->fd();
    channel_maps_.erase(fd);


    int index = ch->mark();
    if (index == kAdded)
    {
        update(EPOLL_CTL_DEL, ch);
    }
    ch->set_mark(kNew);
}

void Poller::update_channel(Channel *ch){
    const int mark = ch->mark();
   
    if (mark == kNew || mark == kDeleted)
    {
        if (mark == kNew)
        {
            int fd = ch->fd();
            channel_maps_[fd] = ch;
        }
        else // index == kAdd
        {

        }
        ch->set_mark(kAdded);
        update(EPOLL_CTL_ADD, ch);
    }
    else // channel已经在Poller中注册过了
    {
        int fd = ch->fd();
        if (ch->events() == 0)
        {
            update(EPOLL_CTL_DEL, ch);
            ch->set_mark(kDeleted);
        }
        else
        {
            update(EPOLL_CTL_MOD, ch);
        }
    }
}

// EventLoop
EventLoop::EventLoop()
    :quit_(false)
    ,looping_(false)
    ,calling_pending_func_(false)
    ,poller_(new Poller(this))
    ,active_channels_(16)
    ,wake_fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC))
    ,wake_channel_(new Channel(this,wake_fd_))
    ,timer_queue_(new TimerQueue(this))
    ,thread_id_(static_cast<pid_t>(::syscall(SYS_gettid)))
{
    wake_channel_->set_read_cb(std::bind(&EventLoop::handle_read,this));
    wake_channel_->enable_read();
}

EventLoop::~EventLoop(){
    
    wake_channel_->disable_all();
    wake_channel_->remove();
    ::close(wake_fd_);
}

void EventLoop::update_channel(Channel *ch){
   poller_->update_channel(ch);
}

void EventLoop::remove_channel(Channel *ch){
    poller_->remove_channel(ch);
}

void EventLoop::wakeup()
{
    uint64_t one = 1;
    ssize_t n = write(wake_fd_, &one, sizeof(one));
    if (n != sizeof(one))
    {
        // error
    }
}

void EventLoop::handle_read()
{
    uint64_t one = 1;
    ssize_t n = read(wake_fd_, &one, sizeof(one));
    if (n != sizeof(one))
    {
        // LOG_ERROR("EventLoop::handleRead() reads %lu bytes instead of 8\n", n);
        // error
    }
}

void EventLoop::add_in_loop(std::function<void()> job){
    {
        std::unique_lock<std::mutex> lock(mtx_);
        jobs_.emplace_back(job);
    }
    if(!is_in_loop_thread() || calling_pending_func_){
        wakeup();
    }
} 

void EventLoop::run_in_loop(func func){
    if(is_in_loop_thread()){
        func();
    }
    else{
        add_in_loop(func);
    }
}

void EventLoop::do_append_jobs(){
    std::vector<std::function<void()>> jobs;
    calling_pending_func_ = true;
    {
        std::unique_lock<std::mutex> lock(mtx_);
        jobs.swap(jobs_); // 交换的方式减少了锁的临界区范围 提升效率 同时避免了死锁 如果执行functor()在临界区内 且functor()中调用queueInLoop()就会产生死锁
    }

    for (const std::function<void()> &func : jobs)
    {
        func(); // 执行当前loop需要执行的回调操作
    }
    calling_pending_func_ = false;
}

void EventLoop::run_at(TimeStamp time,func cb){
    timer_queue_->add_timer(cb,time,0);
}

void EventLoop::run_after(double delay, func cb){
    TimeStamp t(TimeStamp::now().get_micro_seconds() + TimeStamp::kmicro_seconds_per_second*delay);
    timer_queue_->add_timer(cb,t,0);
}

void EventLoop::run_every(double interval, func cb){
    TimeStamp time(TimeStamp::now().get_micro_seconds() + TimeStamp::kmicro_seconds_per_second*interval);
    timer_queue_->add_timer(cb,time,interval);
}

void EventLoop::cancel(Timer *t){
    timer_queue_->cancel(t);
}

void EventLoop::loop(){

    looping_ = true;
    quit_ = false;

    while(!quit_){
        active_channels_.clear();
        active_channels_ = poller_->poll(0);
        for(Channel * ch : active_channels_){
            ch->handle_event();
        }
        do_append_jobs();
    }

    looping_ = false;
}

void EventLoop::quit(){
    quit_ = true;
    if(!is_in_loop_thread()){
        wakeup();
    }
}


EventLoopThread::EventLoopThread(const thread_init_cb &cb,const std::string &name)
    :loop_(nullptr)
    ,exiting_(false)
    ,thread_(std::bind(&EventLoopThread::thread_func,this),name)
    ,mutex_()
    ,cond_()
    ,callback_(cb)
    {
    }

EventLoopThread::~EventLoopThread(){
    exiting_ = true;
    if(loop_ !=nullptr){
        loop_->quit();
        thread_.join();
    }
}

EventLoop * EventLoopThread::start_loop(){
    thread_.start();
    EventLoop *loop = nullptr;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while(loop_ == nullptr){
            cond_.wait(lock);
        }
        loop = loop_;
    }
    return loop;
}

void EventLoopThread::thread_func(){
    EventLoop loop;
    if(callback_){
        callback_(&loop);
    }
    {
        std::unique_lock<std::mutex> lock(mutex_);
        loop_ = &loop;
        cond_.notify_one();
    }
    loop.loop();
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = nullptr;
}

EventLoopThreadPool::EventLoopThreadPool(EventLoop *base_loop,const std::string &nameArg)
    : base_Loop_(base_loop)
    , name_(nameArg)
    , started_(false)
    , num_threads_(0)
    , next_(0)
{

}   

EventLoopThreadPool::~EventLoopThreadPool()
{
    // Don't delete loop, it's stack variable
}

void EventLoopThreadPool::start(const thread_init_cb &cb){
    started_ = true;
    for(int i=0;i<num_threads_;i++){
        char buf[name_.size() + 32];
        snprintf(buf, sizeof buf, "%s%d", name_.c_str(), i);
        EventLoopThread *t = new EventLoopThread(cb, buf);
        threads_.push_back(std::unique_ptr<EventLoopThread>(t));
        loops_.push_back(t->start_loop());   
    }

    if(num_threads_ == 0 && cb){
        cb(base_Loop_);
    }
}

EventLoop * EventLoopThreadPool::get_next_loop(){
    EventLoop *loop = base_Loop_;    // 如果只设置一个线程 也就是只有一个mainReactor 无subReactor 那么轮询只有一个线程 getNextLoop()每次都返回当前的baseLoop_
    if(!loops_.empty())             // 通过轮询获取下一个处理事件的loop
    {
        loop = loops_[next_];
        ++next_;
        if(next_ >= loops_.size())
        {
            next_ = 0;
        }
    }
    return loop;
}

std::vector<EventLoop *> EventLoopThreadPool::get_all_loops()
{
    if(loops_.empty())
    {
        return std::vector<EventLoop *>(1, base_Loop_);
    }
    else
    {
        return loops_;
    }
}

Acceptor::Acceptor(EventLoop *loop,const InetAddress & addr,bool reuse_port)
    : loop_(loop)
    , accept_socket_(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP))
    , accept_channel_(loop,accept_socket_.fd())
    , is_listenning_(false)
{
    accept_socket_.set_reuse_addr(true);
    accept_socket_.set_reuse_port(true);
    accept_socket_.bind_address(addr);

    accept_channel_.set_read_cb(std::bind(&Acceptor::handle_read,this));
    std::cout << __LINE__ << "\t" << accept_socket_.fd() << std::endl;
}

Acceptor::~Acceptor(){
    accept_channel_.disable_all();
    accept_channel_.remove();
}

void Acceptor::listen()
{
    is_listenning_ = true;
    accept_socket_.listen();         // listen
    accept_channel_.enable_read(); // acceptChannel_注册至Poller !重要
}

void Acceptor::handle_read(){
    InetAddress clien_addr;
    int clien_fd = accept_socket_.accept(&clien_addr);

    std::cout << __LINE__ << " Acceptor: " << clien_fd << std::endl;
    if(clien_fd >0){
        if(new_connection_cb_){
            new_connection_cb_(clien_fd,clien_addr);
        }
        else{
            close(clien_fd);
        }
    }
    else{
        // accept error
    }
}


TcpConnection::TcpConnection(EventLoop *loop,int fd,const std::string &name ,const InetAddress & local_addr,const InetAddress & client_addr)
    : loop_(loop)
    , name_(name)
    , local_addr_(local_addr)
    , client_addr_(client_addr)
    , socket_(new Socket(fd))
    , channel_(new Channel(loop,fd))
    , state_(kConnecting)
{
    channel_->set_read_cb( std::bind(&TcpConnection::handleRead,this) );
    channel_->set_write_cb( std::bind(&TcpConnection::handleWrite,this) );
    channel_->set_close_cb( std::bind(&TcpConnection::handleClose,this) );
    channel_->set_error_cb( std::bind(&TcpConnection::handleError,this) );
}

TcpConnection::~TcpConnection(){
   
}

void TcpConnection::handleRead(){
    
    int savedErrno = 0;
    ssize_t n = read_bf_.read_fd(channel_->fd(),&savedErrno);
    if (n > 0) // 有数据到达
    {
        // 已建立连接的用户有可读事件发生了 调用用户传入的回调操作onMessage shared_from_this就是获取了TcpConnection的智能指针
        if(message_cb_){
            message_cb_(shared_from_this(), &read_bf_);
        }
            
    }
    else if (n == 0) // 客户端断开
    {
        handleClose();
    }
    else // 出错了
    {
        
    }
};

void TcpConnection::handleWrite(){
    if(channel_->is_writing()){
        int errno_ = 0;
        int n = write_bf_.write_fd(channel_->fd(),&errno_);
        if(n >= 0){
            write_bf_.retrieve(n);
            if(write_bf_.readable_bytes() == 0){
                channel_->disable_write();

                if(write_complete_cb_){
                    auto func = std::bind(write_complete_cb_,shared_from_this());
                    loop_->add_in_loop(func);
                }

                if(state_ == kDisconnected){
                    shutdown_in_loop();
                }     
            }
                
              
        }
        else{
            // error
        }
    }
    else{

    }   
};

void TcpConnection::send(const std::string &buf)
{
    if (state_ == kConnected)
    {
        if (loop_->is_in_loop_thread()) // 这种是对于单个reactor的情况 用户调用conn->send时 loop_即为当前线程
        {
            send_in_loop(buf.c_str(), buf.size());
        }
        else
        {
            loop_->run_in_loop(
                std::bind(&TcpConnection::send_in_loop, this, buf.c_str(), buf.size()));
        }
    }
}

void TcpConnection::send_in_loop(const void*data,size_t len){
    ssize_t nwrite = 0;
    size_t remaining = len;
    bool fault_error = false;
    // write_bf_.clear();
    if(state_ == kDisconnected){
        // disconnected
    }

    if(!channel_->is_writing() && write_bf_.readable_bytes()==0){
        nwrite = write(channel_->fd(),data,len);
        if (nwrite >= 0)
        {
            remaining = len - nwrite;
            if (remaining == 0 && write_complete_cb_)
            {
                // 既然在这里数据全部发送完成，就不用再给channel设置epollout事件了
                loop_->add_in_loop(
                    std::bind(write_complete_cb_, shared_from_this()));
            }
        }
        else // nwrote < 0
        {
            nwrite = 0;
            if (errno != EWOULDBLOCK) // EWOULDBLOCK表示非阻塞情况下没有数据后的正常返回 等同于EAGAIN
            {
                // LOG_ERROR("TcpConnection::sendInLoop");
                if (errno == EPIPE || errno == ECONNRESET) // SIGPIPE RESET
                {
                    fault_error = true;
                }
            }
        }
    }
    if (!fault_error && remaining > 0)
    {
        // 目前发送缓冲区剩余的待发送的数据的长度
        // size_t oldLen = outputBuffer_.readableBytes();
        // if (oldLen + remaining >= highWaterMark_ && oldLen < highWaterMark_ && highWaterMarkCallback_)
        // {
        //     loop_->queueInLoop(
        //         std::bind(highWaterMarkCallback_, shared_from_this(), oldLen + remaining));
        // }
        write_bf_.append((char *)data + nwrite, remaining);
        if (!channel_->is_writing())
        {
            channel_->enable_write(); // 这里一定要注册channel的写事件 否则poller不会给channel通知epollout
        }
    }
}

void TcpConnection::shutdown(){
    if (state_ == kConnected)
    {
        set_state(kDisconnecting);
        loop_->run_in_loop(
            std::bind(&TcpConnection::shutdown_in_loop, this));
    }
}

void TcpConnection::shutdown_in_loop(){
    if (!channel_->is_writing()) // 说明当前outputBuffer_的数据全部向外发送完成
    {
        socket_->shutdown_write();
    }
}

void TcpConnection::handleClose(){
    set_state(kDisconnected);
    channel_->disable_all();

    std::shared_ptr<TcpConnection> connPtr(shared_from_this());
    connection_cb_(connPtr); // 执行连接关闭的回调
    close_cb_(connPtr);      // 执行关闭连接的回调 执行的是TcpServer::removeConnection回调方法   // must be the last line
};

void TcpConnection::handleError(){
    // error
};

void TcpConnection::connection_established(){
    set_state(kConnected);
    // channel_->tie(shared_from_this());
    channel_->enable_read(); // 向poller注册channel的EPOLLIN读事件

    // 新连接建立 执行回调
    connection_cb_(shared_from_this());
}

void TcpConnection::connection_destroyed(){
    if(state_ == kConnected){
        set_state(kDisconnected);
        channel_->disable_all();
        connection_cb_(shared_from_this());
    }
    channel_->remove();
}

TcpServer::TcpServer(EventLoop *loop,InetAddress &addr)
    : loop_(loop)
    , acceptor_(new Acceptor(loop_,addr,true))
    , thread_pool_(new EventLoopThreadPool(loop,"bb"))
    , next_conn_id_(1)
    // , started_(0)
{
    acceptor_->set_new_connetion_cb(
        std::bind(&TcpServer::new_connection, this, std::placeholders::_1, std::placeholders::_2));
}

TcpServer::~TcpServer(){
    for(auto &item : connection_maps_)
    {
        tcp_connection_ptr conn(item.second);
        item.second.reset();    // 把原始的智能指针复位 让栈空间的TcpConnectionPtr conn指向该对象 当conn出了其作用域 即可释放智能指针指向的对象
        // 销毁连接
        conn->get_loop()->run_in_loop(
            std::bind(&TcpConnection::connection_destroyed, conn));
    }
}

void TcpServer::start(){
    thread_pool_->start(thread_init_cb_);
    loop_->run_in_loop(std::bind(&Acceptor::listen,acceptor_));
    // loop_->loop();
}

void TcpServer::new_connection(int client_fd, const InetAddress &client_addr){

    EventLoop * cur_loop = thread_pool_->get_next_loop();

    next_conn_id_ ++;
    sockaddr_in local;
    memset(&local,0,sizeof(local));
    socklen_t addrlen = sizeof(local);

    InetAddress local_addr(local);
    tcp_connection_ptr conn(new TcpConnection(cur_loop,client_fd,std::to_string(next_conn_id_),local_addr,client_addr));

    connection_maps_[std::to_string(next_conn_id_)] = conn;
    conn->set_connection_cb(connection_cb_);
    conn->set_write_complete_cb(write_complete_cb_);
    conn->set_message_cb(message_cb_);

    conn->set_close_cb(
        std::bind(&TcpServer::remove_connection, this, std::placeholders::_1));

    cur_loop->run_in_loop(std::bind(&TcpConnection::connection_established, conn));
}

void TcpServer::remove_connection(const tcp_connection_ptr &conn){
    loop_->run_in_loop(
        std::bind(&TcpServer::remove_connection_in_loop, this, conn));
}

void TcpServer::remove_connection_in_loop(const tcp_connection_ptr &conn){
    connection_maps_.erase(conn->name());
    EventLoop *cur_loop = conn->get_loop();
    cur_loop->add_in_loop(std::bind(&TcpConnection::connection_destroyed,conn));
}



