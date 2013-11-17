#include "linux_device.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

static int GetDeviceMajor(const string& name) {
    ifstream devices("/proc/devices");
    while (devices.good()) {
        string line;
        getline(devices, line);
        stringstream ss;
        ss << line << " ";
        int major;
        string device;
        ss >> major >> device;
        if (ss.good() && device == name) {
            return major;
        }
    }
    throw runtime_error("Could not get device major.");
}

static bool DeviceFileExists(const string& path, int dev_major) {
    struct stat stat;
    if (lstat(path.c_str(), &stat) != 0) {
        switch (errno) {
        case ENOENT:
            return false;
        default:
            throw runtime_error(
                string("Could not lstat the device file: ") + strerror(errno));
        }
    }
    if (major(stat.st_rdev) != (unsigned int) dev_major) {
        throw runtime_error("The device exists but it has the wrong major.");
    }
    return true;
}

static void CreateDevFile(const string& path, int major) {
    if (mknod(path.c_str(), S_IFCHR, makedev(major, 0)) != 0) {
        throw runtime_error(
            string("Could not mknod the device file: ") + strerror(errno));
    }
    if (chmod(path.c_str(), S_IROTH) != 0) {
        throw runtime_error(
            string("Could not make the dev file readable: ") + strerror(errno));
    }
}

LinuxDevice::LinuxDevice(const string& name, const string& path) : path_(path) {
    major_ = GetDeviceMajor(name);
    if (!DeviceFileExists(path, major_)) {
        CreateDevFile(path, major_);
    }
    OpenDevFile();
}

void LinuxDevice::OpenDevFile() {
    fd_ = open(path_.c_str(), O_RDONLY);
    if (fd_ == -1) {
        throw runtime_error(string("Could not open device: ") + strerror(errno));
    }
}

int LinuxDevice::Ioctl(int request, void* argp, bool non_zero_is_error) {
    int result = ioctl(fd_, request, argp);
    if (result != 0 && non_zero_is_error) {
        throw new runtime_error("ioctl returned non-zero");
    }
    return result;
}

LinuxDevice::~LinuxDevice() {
    if (close(fd_) != 0) {
        // Can't throw an exception from a destructor.
        cerr << "Could not close the device file descriptor: "
             << strerror(errno) << endl;
    }
}
