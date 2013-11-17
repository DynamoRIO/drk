extern "C" {
#include "hypercall_host_module.h"
#include "hypercall.h"
}

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>

#include "linux_device.h"

using namespace std;

class HypercallDevice {
  public:
    HypercallDevice() :
            device_(HYPERCALL_DEVICE_NAME, HYPERCALL_DEVICE_PATH) {
        hypercall_ = (hypercall_t*) new char[HYPERCALL_MAX_SIZE];
    }
    
    const hypercall_t& Dequeue() {
        device_.Ioctl(HYPERCALL_IOCTL_DEQUEUE, hypercall_, true);
        if (hypercall_->size > HYPERCALL_MAX_SIZE) {
            throw runtime_error("The kernel returned a hypercall larger than "
                                "HYPERCALL_MAX_SIZE.");
        }
        return *hypercall_;
    }

    void Clear() {
        device_.Ioctl(HYPERCALL_IOCTL_CLEAR, NULL, true);
    }

    ~HypercallDevice() {
        delete (char*) hypercall_;
    }
  private:
    hypercall_t* hypercall_;
    LinuxDevice device_;
};

class FileSystem {
 public:
    virtual void Open(int fd, const string& path) = 0;
    virtual void Close(int fd) = 0;
    virtual void Write(int fd, const char* data, int count) = 0;
    virtual void Flush(int fd) = 0;
    virtual ~FileSystem() {}
};

class StdoutFileSystem : public FileSystem {
  public:
    void Open(int fd, const string& path) { }

    void Close(int fd) { }

    void Write(int fd, const char* data, int count) {
        cout.rdbuf()->sputn(data, count);
    }

    void Flush(int fd) {
        cout.flush();
    }
};

class SimpleFileSystem : public FileSystem {
  public:
    SimpleFileSystem(const string& root) {
        InitParentDirectory(root);
        CreateFile(1, "/stdout");
        CreateFile(2, "/stderr");
    }

    ~SimpleFileSystem() {
        for (FileIterator i = files_.begin(); i != files_.end(); ++i) {
            delete i->second;
        }
    }

    void Open(int fd, const string& path) {
        CreateFile(fd, path);
    }

    void Close(int fd) {
        delete files_[fd];
        files_.erase(fd);
    }

    void Write(int fd, const char* data, int count) {
        files_[fd]->rdbuf()->sputn(data, count);
        Flush(fd);
    }

    void Flush(int fd) {
        files_[fd]->flush();
    }

  private:
    void CreateFile(int fd, const string& path) {
        // If the file already exists, then we're going to overwrite it.
        ostream* stream = new ofstream((parent_ + "/" + path).c_str());
        files_[fd] = stream;
    }

    void InitParentDirectory(const string& root) {
        string time = GetTime();
        stringstream parent_ss;
        parent_ss << root << "/" << time;
        parent_ = parent_ss.str();
        if (mkdir(parent_.c_str(), 0750) != 0) {
            stringstream error;
            error << "Could not create parent directory " <<
                     parent_ << ": " << strerror(errno);
            throw runtime_error(error.str());
        }
        string latest = root + "/latest";
        unlink(latest.c_str());
        symlink(time.c_str(), latest.c_str());
    }

    static string GetTime() {
        stringstream time_ss;
        time_ss << time(NULL);
        return time_ss.str();
    }

    string parent_;
    map<int, ostream*> files_;
    typedef map<int, ostream*>::iterator FileIterator;
};

class DualFileSystem : public FileSystem {
  public:
    DualFileSystem(FileSystem* a, FileSystem* b) : a_(a), b_(b) {
    }

    ~DualFileSystem() {
        delete a_;
        delete b_;
    }

    void Open(int fd, const string& path) {
        a_->Open(fd, path);
        b_->Open(fd, path);
    }

    void Close(int fd) { 
        a_->Close(fd);
        b_->Close(fd);
    }

    void Write(int fd, const char* data, int count) {
        a_->Write(fd, data, count);
        b_->Write(fd, data, count);
    }

    void Flush(int fd) {
        a_->Flush(fd);
        b_->Flush(fd);
    }

  private:
    FileSystem* a_;
    FileSystem* b_;
};

class HypercallServer {
  public:
    HypercallServer(const string& file_system_root) :
        file_system_(new StdoutFileSystem),
        file_system_root_(file_system_root) {
    }

    ~HypercallServer() {
        delete file_system_;
    }

    void HandleHypercall(const hypercall_t& hypercall) {
        switch (hypercall.type) {
        case HYPERCALL_NOP:
            HandleNOP((const hypercall_nop_t&) hypercall);
            break;
        case HYPERCALL_INIT:
            HandleInit((const hypercall_init_t&) hypercall);
            break;
        case HYPERCALL_OPEN:
            HandleOpen((const hypercall_open_t&) hypercall);
            break;
        case HYPERCALL_CLOSE:
            HandleClose((const hypercall_close_t&) hypercall);
            break;
        case HYPERCALL_WRITE:
            HandleWrite((const hypercall_write_t&) hypercall);
            break;
        case HYPERCALL_FLUSH:
            HandleFlush((const hypercall_flush_t&) hypercall);
            break;
        default:
            throw runtime_error("Unknown hypercall type.");
        }
    }

  private:

    void HandleNOP(const hypercall_nop_t& hc) {
        /* This just means that we were interrupted when we made an ioctl. Treat
         * this as a nop. */
    }

    void HandleInit(const hypercall_init_t& hc) {
        delete file_system_;
        file_system_ = new SimpleFileSystem(file_system_root_);
    }

    void HandleOpen(const hypercall_open_t& hc) {
        file_system_->Open(hc.fd, &hc.fname);
    }

    void HandleClose(const hypercall_close_t& hc) {
        file_system_->Close(hc.fd);
    }

    void HandleWrite(const hypercall_write_t& hc) {
        file_system_->Write(hc.fd, &hc.buffer, hc.count);
    }

    void HandleFlush(const hypercall_flush_t& hc) {
        file_system_->Flush(hc.fd);
    }

    FileSystem* file_system_;
    const string file_system_root_;
};


int main(int argc, char** argv) {
    try {
        HypercallDevice device;
        if (argc == 2 && string(argv[1]) == "clear") {
            device.Clear();    
        } else {
            HypercallServer server("./logs");
            for (;;) {
                server.HandleHypercall(device.Dequeue());
            }
        }
    } catch (const runtime_error& e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
