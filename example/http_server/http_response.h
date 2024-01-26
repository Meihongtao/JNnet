#pragma once

#include <map>
#include <string>
#include <JNnet.h>

class HttpResponse
{
public:
    enum HttpStatusCode
    {
        kUnknown,
        k200Ok = 200,
        k301MovedPermanently = 301,
        k400BadRequest = 400,
        k404NotFound = 404,
    };

    explicit HttpResponse(bool close)
        : status_code_(kUnknown),
          close_connection_(close)
    {
    }

    void set_status_code(HttpStatusCode code)
    {
        status_code_ = code;
    }

    void set_status_message(const std::string &message)
    {
        status_message_ = message;
    }

    void set_close_connection(bool on)
    {
        close_connection_ = on;
    }

    bool close_connection() const
    {
        return close_connection_;
    }

    void set_content_type(const std::string &contentType)
    {
        add_header("Content-Type", contentType);
    }

    // FIXME: replace string with StringPiece
    void add_header(const std::string &key, const std::string &value)
    {
        headers_[key] = value;
    }

    void set_body(const std::string &body)
    {
        body_ = body;
    }

    void append_to_buffer(Buffer *output) const
    {
        char buf[32];
        snprintf(buf, sizeof buf, "HTTP/1.1 %d ", status_code_);
        output->append(buf);
        output->append(status_message_);
        output->append("\r\n");

        if (close_connection_)
        {
            output->append("Connection: close\r\n");
        }
        else
        {
            snprintf(buf, sizeof buf, "Content-Length: %zd\r\n", body_.size());
            output->append(buf);
            output->append("Connection: Keep-Alive\r\n");
        }

        for (const auto &header : headers_)
        {
            output->append(header.first);
            output->append(": ");
            output->append(header.second);
            output->append("\r\n");
        }

        output->append("\r\n");
        output->append(body_);
    };

private:
    std::map<std::string, std::string> headers_;
    HttpStatusCode status_code_;
    // FIXME: add http version
    std::string status_message_;
    bool close_connection_;
    std::string body_;
};