#include <JNnet.h>
#include <iostream>
int main(){
    EventLoop *loop = new EventLoop();
    InetAddress addr = InetAddress(3232,"127.0.0.1");
    TcpServer * server = new TcpServer(loop,addr);

    server->set_connetion_cb([](const std::shared_ptr<TcpConnection> &conn){
        if(conn->connected())
            std::cout << "new connection coming ! "<< conn->get_fd() << " " << conn->get_client_addr().to_ipport() << std::endl;
        else
            std::cout << "connection down ! "<< conn->get_fd() << " " << conn->get_client_addr().to_ipport() << std::endl;
    });

    server->set_message_cb([](const std::shared_ptr<TcpConnection> &conn,Buffer *buf){
        std::string str = buf->retrieve_all_asstring();
        conn->send(str);

        std::cout << "message from " << conn->get_client_addr().to_ipport() << std::endl;
        std::cout << "message content is:" << str << std::endl;
    });
    
    server->start();
    loop->loop();
    return 0;
}