#include <JNnet.h>

#include "http_context.h"
#include "http_request.h"
#include "http_response.h"

template<typename T, typename... Ts>
std::unique_ptr<T> make_unique(Ts&&... params)
{
   return std::unique_ptr<T>(new T(std::forward<Ts>(params)...));
}

namespace detail
{
    bool benchmark = true;
    void defaultHttpCallback(const HttpRequest &req, HttpResponse *resp)
    {
        std::cout << "Headers " << req.methodString() << " " << req.path() << std::endl;
        if (!benchmark)
        {
            const std::map<std::string, std::string>& headers = req.headers();
            for (const auto& header : headers)
            {
            std::cout << header.first << ": " << header.second << std::endl;
            }
        }

        if (req.path() == "/")
        {
            resp->set_status_code(HttpResponse::k200Ok);
            resp->set_status_message("OK");
            resp->set_content_type("text/html");
            resp->add_header("Server", "JNnet");
            // string now = Timestamp::now().toFormattedString();
            resp->set_body("<html><head><title>This is title</title></head>"
                "<body><h1>Hello</h1>This is index Page "
                "</body></html>");
        }
        else if (req.path() == "/favicon.ico")
        {
            resp->set_status_code(HttpResponse::k200Ok);
            resp->set_status_message("OK");
            resp->set_content_type("image/png");
            // resp->set_body(string(favicon, sizeof favicon));
        }
        else if (req.path() == "/hello")
        {
            resp->set_status_code(HttpResponse::k200Ok);
            resp->set_status_message("OK");
            resp->set_content_type("text/plain");
            resp->add_header("Server", "Muduo");
            resp->set_body("hello, world!\n");
        }
        else
        {
            resp->set_status_code(HttpResponse::k404NotFound);
            resp->set_status_message("Not Found");
            resp->set_close_connection(true);
        }
    }

} // namespace detail

class HttpServer : noncopyable
{
public:
    using HttpCallback = std::function<void(const HttpRequest &, HttpResponse *)>;

    HttpServer(EventLoop *loop,
                InetAddress &listenAddr,
               const std::string &name)
        
        : httpCallback_(detail::defaultHttpCallback)
        , server_(loop,listenAddr)
    {
        server_.set_connetion_cb(
            std::bind(&HttpServer::on_connection, this, std::placeholders::_1));
        server_.set_message_cb(
            std::bind(&HttpServer::on_message, this, std::placeholders::_1, std::placeholders::_2));
    };

    EventLoop *getLoop() const { return server_.get_loop(); }

    /// Not thread safe, callback be registered before calling start().
    void setHttpCallback(const HttpCallback &cb)
    {
        httpCallback_ = cb;
    }

    void set_thread_nums(int numThreads)
    {
        server_.set_thread_nums(numThreads);
    }

    void start()
    {
        server_.start();
    };

private:
    void on_connection(const tcp_connection_ptr &conn){
        if (conn->connected())
        {
            // conn->set(HttpContext());
        }
    };
    void on_message(const tcp_connection_ptr &conn, Buffer *buf)
    {
        std::unique_ptr<HttpContext> context = make_unique<HttpContext>();

        // std::cout << "Get :" << buf->get_content() << std::endl;

        if (!context->parse_request(buf))
        {
            std::cout << __LINE__ <<" Bad Request !" << std::endl;
            

            conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
            conn->shutdown();
        }

        if (context->got_all())
        {
            on_request(conn, context->request());
            context->reset();
        }
    };

    void on_request(const tcp_connection_ptr &conn, const HttpRequest &req)
    {
        const std::string &connection = req.get_header("Connection");
        bool close = connection == "close" ||
                     (req.get_version() == HttpRequest::kHttp10 && connection != "Keep-Alive");
        HttpResponse response(close);
        httpCallback_(req, &response);
        Buffer buf;
        std::cout << __LINE__ <<" On Request !" << std::endl;
        response.append_to_buffer(&buf);
        conn->send(buf.retrieve_all_asstring());
        if (response.close_connection())
        {
            conn->shutdown();
        }
    };

    TcpServer server_;
    HttpCallback httpCallback_;
};

int main(){
    EventLoop *loop = new EventLoop();
    InetAddress addr = InetAddress(7788,"172.21.140.98");
    //  InetAddress addr = InetAddress(7788,"127.0.0.1");
    // TcpServer * server = new TcpServer(loop,addr);
    HttpServer * server = new HttpServer(loop,addr,"as");
    server->start();
    loop->loop();
    // server->set_connetion_cb([](const std::shared_ptr<TcpConnection> &conn){
    //     if(conn->connected())
    //         std::cout << "new connection coming ! "<< conn->get_fd() << " " << conn->get_client_addr().to_ipport() << std::endl;
    //     else
    //         std::cout << "connection down ! "<< conn->get_fd() << " " << conn->get_client_addr().to_ipport() << std::endl;
    // });

    // server->set_message_cb([](const std::shared_ptr<TcpConnection> &conn,Buffer *buf){
    //     std::string str = buf->retrieve_all_asstring();
    //     conn->send(str);

    //     std::cout << "message from " << conn->get_client_addr().to_ipport() << std::endl;
    //     std::cout << "message content is:" << str << std::endl;
    // });
}
