/*
 * Note: This file is compiled and executed in userspace (as part of the
 * userspace controller utility), NOT inside the Linux kernel. Therefore,
 * standard C++ library headers are permitted.
 *
 * TODO: Standard C++ exceptions are disallowed in DynamoRIO's general C++
 * coding style. We should replace standard C++ exceptions with a different
 * error-handling mechanism, such as standard error codes or boolean status
 * returns, to maximize code interoperability and style consistency.
 */

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
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace dynamorio {
namespace kernel {
namespace {

int
GetDeviceMajor(const std::string &name)
{
    std::ifstream devices("/proc/devices");
    while (devices.good()) {
        std::string line;
        std::getline(devices, line);
        std::stringstream ss;
        ss << line << " ";
        int major;
        std::string device;
        ss >> major >> device;
        if (ss.good() && device == name) {
            return major;
        }
    }
    throw std::runtime_error("Could not get device major.");
}

bool
DeviceFileExists(const std::string &path, int dev_major)
{
    struct stat stat;
    if (lstat(path.c_str(), &stat) != 0) {
        switch (errno) {
        case ENOENT: return false;
        default:
            throw std::runtime_error(std::string("Could not lstat the device file: ") +
                                     strerror(errno));
        }
    }
    if (major(stat.st_rdev) != (unsigned int)dev_major) {
        throw std::runtime_error("The device exists but it has the wrong major.");
    }
    return true;
}

void
CreateDevFile(const std::string &path, int major)
{
    if (mknod(path.c_str(), S_IFCHR, makedev(major, 0)) != 0) {
        throw std::runtime_error(std::string("Could not mknod the device file: ") +
                                 strerror(errno));
    }
    if (chmod(path.c_str(), S_IROTH) != 0) {
        throw std::runtime_error(std::string("Could not make the dev file readable: ") +
                                 strerror(errno));
    }
}

} // namespace

LinuxDevice::LinuxDevice(const std::string &name, const std::string &path)
    : path_(path)
{
    major_ = GetDeviceMajor(name);
    if (!DeviceFileExists(path, major_)) {
        CreateDevFile(path, major_);
    }
    OpenDevFile();
}

void
LinuxDevice::OpenDevFile()
{
    fd_ = open(path_.c_str(), O_RDONLY);
    if (fd_ == -1) {
        throw std::runtime_error(std::string("Could not open device: ") +
                                 strerror(errno));
    }
}

int
LinuxDevice::Ioctl(int request, void *argp, bool non_zero_is_error)
{
    int result = ioctl(fd_, request, argp);
    if (result != 0 && non_zero_is_error) {
        throw std::runtime_error("ioctl returned non-zero");
    }
    return result;
}

LinuxDevice::~LinuxDevice()
{
    if (close(fd_) != 0) {
        // Can't throw an exception from a destructor.
        std::cerr << "Could not close the device file descriptor: " << strerror(errno)
                  << std::endl;
    }
}

} // namespace kernel
} // namespace dynamorio
