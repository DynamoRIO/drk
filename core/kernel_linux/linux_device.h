#ifndef __LINUX_DEVICE_H_
#define __LINUX_DEVICE_H_

#include <string>

namespace dynamorio {
namespace kernel {

class LinuxDevice {
public:
    LinuxDevice(const std::string &name, const std::string &path);
    ~LinuxDevice();

    int
    Ioctl(int request, void *argp, bool non_zero_is_error = false);

private:
    void
    OpenDevFile();

    int major_;
    int fd_;
    const std::string path_;

    // Intentionally not implemented.
    LinuxDevice(const LinuxDevice &);
    LinuxDevice &
    operator=(const LinuxDevice &);
};

} // namespace kernel
} // namespace dynamorio

#endif
