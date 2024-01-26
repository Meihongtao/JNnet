#include "../../combine.h"

class TimeTaskServer{
public:
    TimeTaskServer(EventLoop *loop,InetAddress &addr)
    :loop_(loop),addr_(addr),server_(new TcpServer(loop_,addr_))
    {
        server_->set_connetion_cb(std::bind(&TimeTaskServer::connection_cb,this,std::placeholders::_1));
    }
    
    void start(){
        server_->start();
    }

    void set_thread_nums(int n){
        server_->set_thread_nums(n);
    }

    void connection_cb(const tcp_connection_ptr &conn){
        if(conn->connected()){
            std::string str = "Time is: "+ TimeStamp::now().to_string()+'\n';
            conn->send(str);
            add_time_task(conn);
        }
        else{

        }
    }

    void add_time_task(const tcp_connection_ptr &conn){
        EventLoop * loop = server_->get_loop();
        loop->run_every(3,[&conn](){
                if(conn && conn->connected()){
                    std::string str = "Time is: "+ TimeStamp::now().to_string()+"\n";
                    conn->send(str);
                }
                else{
                    
                    std::cout << "connection quit!\n";
                }
            });
    }


private:
    EventLoop *loop_;
    InetAddress addr_;
    std::unique_ptr<TcpServer> server_;

};

int main(){
    EventLoop * loop = new EventLoop();
    InetAddress addr(8899,"127.0.0.1");
    TimeTaskServer *server = new TimeTaskServer(loop,addr);
    server->start();
    loop->loop();

}