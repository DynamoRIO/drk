#include <stdlib.h>
extern "C" {
#include "dynamorio_controller_module.h"
}

#include <cstring>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sched.h>
#include <stdio.h>

#include "linux_device.h"
#include "controller_stats_interface.h"

using namespace std;

class DynamoRIODevice {
  public:
    DynamoRIODevice() : device_(DYNAMORIO_DEVICE_NAME, DYNAMORIO_DEVICE_PATH) {
    }

    void Init(const string& options) {
        dynamorio_init_cmd_t cmd;
        /* Add 1 for the NULL terminator. */
        if (options.size() + 1 > KERNEL_ENV_VALUE_MAX) {
            stringstream ss;
            ss << "Options string \"" << options << "\" exceeds the " <<
                  KERNEL_ENV_VALUE_MAX << " character limit.";
            throw runtime_error(ss.str());
        }
        strcpy(cmd.options, options.c_str());
        if (device_.Ioctl(DYNAMORIO_IOCTL_INIT, &cmd) != 0) {
            throw runtime_error("DYNAMORIO_IOCTL_INIT failed. Have you already "
                                "initialized the module? You can only do it "
                                "once.");
        }
    }

    void Exit() {
        dynamorio_exit_cmd_t cmd;
        if (device_.Ioctl(DYNAMORIO_IOCTL_EXIT, &cmd) != 0) {
            throw runtime_error("DYNAMORIO_IOCTL_EXIT failed. Have you run init"
                                " yet? Have you already exited?");
        }
    }

    void GetKStats(dynamorio_kstats_cmd_t *kstats) {
        if (device_.Ioctl(DYNAMORIO_IOCTL_KSTATS, kstats) != 0) {
            throw runtime_error("DYNAMORIO_IOCTL_KSTATS failed. Check dmesg.");
        }
    }

    void GetStats(dynamorio_stats_cmd_t *stats) {
        if (device_.Ioctl(DYNAMORIO_IOCTL_STATS, stats) != 0) {
            throw runtime_error("DYNAMORIO_IOCTL_STATS failed. Check dmesg.");
        }
    }

  private:
    LinuxDevice device_;
};

static void handle_init(int argc, char** argv) {
    const char* options = "";
    if (argc < 2 || argc > 3 || string(argv[1]) != "init") {
        throw runtime_error("Usage: controller init [\"options\"]");
    }
    if (argc == 3) {
        options = argv[2];
    }
    cout << "Options: " << options << endl;
    DynamoRIODevice device;
    device.Init(options);
}

static void handle_exit(int argc, char** argv) {
    if (argc != 2 || string(argv[1]) != "exit") {
        throw runtime_error("Usage: controller exit");
    }
    DynamoRIODevice device;
    device.Exit();
}

static int get_cpu_count() {
    FILE *pipe = popen("cat /proc/cpuinfo | grep processor | wc -l", "r");
    if (!pipe) {
        throw runtime_error("get_cpu_count: popen failed.");
    }
    int result;
    if (fscanf(pipe, "%d", &result) != 1) {
        throw runtime_error("get_cpu_count: fscanf failed.");
    }
    if (pclose(pipe) == -1) {
        throw runtime_error("get_cpu_count: pclose failed.");
    }
    return result;
}

static void handle_kstats(int argc, char** argv) {
    if (argc != 2 || string(argv[1]) != "kstats") {
        throw runtime_error("Usage: controller kstats");
    }
    DynamoRIODevice device;
    int cpu_count = get_cpu_count();
    cout << "[" << endl;
    for (int cpu = 0; cpu < cpu_count; cpu++) {
        dynamorio_kstats_cmd_t kstats; 
        kstats.cpu = cpu;
        device.GetKStats(&kstats);
        dump_kstats(&kstats.buffer.data, kstats.buffer.size, cout);
        if (cpu != cpu_count - 1) {
            cout << ",";
        }
    }
    cout << "]" << endl;
}

static void handle_stats(int argc, char** argv) {
    if (argc != 2 || string(argv[1]) != "stats") {
        throw runtime_error("Usage: controller stats");
    }
    DynamoRIODevice device;
    dynamorio_stats_cmd_t stats; 
    device.GetStats(&stats);
    dump_stats(&stats.buffer.data, stats.buffer.size, cout);
}

static void show_usage(int argc, char** argv) {
    cerr << "Usage: controller <subcommand>" << endl;
    cerr << endl;
    cerr << "Available subcommands:" << endl;
    cerr << "   init [options] - initilizes the module and takes over" << endl;
    cerr << "   exit - returns to native execution" << endl;
    cerr << "   kstats - dumps kstats to the screen" << endl;
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            show_usage(argc, argv);
            return EXIT_FAILURE;
        }
        string cmd = string(argv[1]);

        if (cmd == "init") {
            handle_init(argc, argv);
        } else if (cmd == "exit") {
            handle_exit(argc, argv);
        } else if (cmd == "kstats") {
            handle_kstats(argc, argv);
        } else if (cmd == "stats") {
            handle_stats(argc, argv);
        } else {
            show_usage(argc, argv);
            return EXIT_FAILURE;
        }

    } catch (const runtime_error& e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
