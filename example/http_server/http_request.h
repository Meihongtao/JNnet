#pragma once

#include<string>
#include<map>
#include<assert.h>

class HttpRequest
{
public:
    enum Method
    {
        kInvalid,
        kGet,
        kPost,
        kHead,
        kPut,
        kDelete
    };
    enum Version
    {
        kUnknown,
        kHttp10,
        kHttp11
    };

    HttpRequest()
        : method_(kInvalid),
          version_(kUnknown)
    {
    }

    void set_version(Version v)
    {
        version_ = v;
    }

    Version get_version() const
    {
        return version_;
    }

    bool set_method(const char *start, const char *end)
    {
        assert(method_ == kInvalid);
        std::string m(start, end);
        if (m == "GET")
        {
            method_ = kGet;
        }
        else if (m == "POST")
        {
            method_ = kPost;
        }
        else if (m == "HEAD")
        {
            method_ = kHead;
        }
        else if (m == "PUT")
        {
            method_ = kPut;
        }
        else if (m == "DELETE")
        {
            method_ = kDelete;
        }
        else
        {
            method_ = kInvalid;
        }
        return method_ != kInvalid;
    }

    Method method() const
    {
        return method_;
    }

    const char *methodString() const
    {
        const char *result = "UNKNOWN";
        switch (method_)
        {
        case kGet:
            result = "GET";
            break;
        case kPost:
            result = "POST";
            break;
        case kHead:
            result = "HEAD";
            break;
        case kPut:
            result = "PUT";
            break;
        case kDelete:
            result = "DELETE";
            break;
        default:
            break;
        }
        return result;
    }

    void set_path(const char *start, const char *end)
    {
        path_.assign(start, end);
    }

    const std::string &path() const
    {
        return path_;
    }

    void set_query(const char *start, const char *end)
    {
        query_.assign(start, end);
    }

    

    const std::string &query() const
    {
        return query_;
    }

    // void setReceiveTime(Timestamp t)
    // {
    //     receiveTime_ = t;
    // }

    // Timestamp receiveTime() const
    // {
    //     return receiveTime_;
    // }

    void add_header(const char *start, const char *colon, const char *end)
    {
        std::string field(start, colon);
        ++colon;
        while (colon < end && isspace(*colon))
        {
            ++colon;
        }
        std::string value(colon, end);
        while (!value.empty() && isspace(value[value.size() - 1]))
        {
            value.resize(value.size() - 1);
        }
        headers_[field] = value;
    }

    std::string get_header(const std::string &field) const
    {
        std::string result;
        std::map<std::string, std::string>::const_iterator it = headers_.find(field);
        if (it != headers_.end())
        {
            result = it->second;
        }
        return result;
    }

    const std::map<std::string, std::string> &headers() const
    {
        return headers_;
    }

    void swap(HttpRequest &that)
    {
        std::swap(method_, that.method_);
        std::swap(version_, that.version_);
        path_.swap(that.path_);
        query_.swap(that.query_);
        // receiveTime_.swap(that.receiveTime_);
        headers_.swap(that.headers_);
    }

private:
    Method method_;
    Version version_;
    std::string path_;
    std::string query_;
    // Timestamp receiveTime_;
    std::map<std::string, std::string> headers_;
};
