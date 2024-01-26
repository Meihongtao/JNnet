#pragma once

#include <JNnet.h>
#include "http_request.h"

class HttpContext{
public:
    enum HttpRequestParseState
    {
        kExpectRequestLine,
        kExpectHeaders,
        kExpectBody,
        kGotAll,
    };

    HttpContext()
    : state_(kExpectRequestLine)
    {
    }

    const HttpRequest& request() const { return request_; }

    HttpRequest& request() { return request_; }

    bool got_all() const { return state_ == kGotAll; }
  
    bool process_request_line(const char * begin,const char *end){
        bool succeed = false;
        const char* start = begin;
        const char* space = std::find(start, end, ' ');
        if (space != end && request_.set_method(start, space))
        {
            start = space+1;
            space = std::find(start, end, ' ');
            if (space != end)
            {
            const char* question = std::find(start, space, '?');
            if (question != space)
            {
                request_.set_path(start, question);
                request_.set_query(question, space);
            }
            else
            {
                request_.set_path(start, space);
            }
            start = space+1;
            succeed = end-start == 8 && std::equal(start, end-1, "HTTP/1.");
            if (succeed)
            {
                if (*(end-1) == '1')
                {
                request_.set_version(HttpRequest::kHttp11);
                }
                else if (*(end-1) == '0')
                {
                request_.set_version(HttpRequest::kHttp10);
                }
                else
                {
                succeed = false;
                }
            }
            }
        }
        return succeed;
    }

    bool parse_request(Buffer *buf){
        bool ok = true;
        bool hasMore = true;
        while(hasMore){
            if(state_ == kExpectRequestLine){
                const char *crlf = buf->find_CRLF();
                if(crlf){
                    ok = process_request_line(buf->peek(),crlf);
                    if(ok){
                        buf->retrieve_until(crlf+2);
                        state_ = kExpectHeaders;
                    }
                    else{
                        hasMore = false;
                    }
                }else{
                    hasMore = false;
                }
            }
            else if(state_ == kExpectHeaders){
                const char* crlf = buf->find_CRLF();
                if (crlf)
                {
                    const char* colon = std::find(buf->peek(), crlf, ':');
                    if (colon != crlf)
                    {
                        request_.add_header(buf->peek(), colon, crlf);
                    }
                    else
                    {
                        // empty line, end of header
                        // FIXME:
                        state_ = kGotAll;
                        hasMore = false;
                    }
                    buf->retrieve_until(crlf + 2);
                }
                else
                {
                    hasMore = false;
                }
            }
            else if (state_ == kExpectBody)
            {
            // FIXME:
            }
        }
        return ok;
    };

    void reset(){
        state_ = kExpectRequestLine;
        HttpRequest dummy;
        request_.swap(dummy);
    }
private:
    HttpRequestParseState state_;
    HttpRequest request_;
};