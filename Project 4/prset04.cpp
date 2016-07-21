#include <memory>
#include <algorithm>
#include <string>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <deque>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <glog/logging.h>

#define DO_FORK

namespace fs = boost::filesystem;
namespace opts = boost::program_options;

/**
 * Configuration.
 */
struct Config {
    uint16_t port_ = 12000;
};

/**
 * Exception.
 */
class Exception : public std::exception {
public:
    /**
     * Constructor.
     *
     * @param msg Message.
     */
    explicit Exception(const std::string& msg) : msg_(msg) {
    }

    virtual const char* what(void) const noexcept {
        return msg_.c_str();
    }

private:
    const std::string msg_;
};

/**
 * Exit with an error message.
 *
 * @param desc Options.
 * @param msg Message.
 */
static void ExitError(opts::options_description& desc, const std::string msg) {
    std::cout << desc << "\nERROR: " << msg << ".\n";
    exit(1);
}

/**
 * Parse arguments.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param[out] conf Configuration.
 */
static void ParseArgs(int argc, char** argv, Config& conf) {
    std::stringstream usage;
    usage << "Usage: " PROJECT_NAME " <command> [options]";
    opts::options_description visible_desc(usage.str());

    try {
        opts::options_description common_desc("# Common options");
        common_desc.add_options()
            ("config", opts::value<std::string>(), "Path to configuration file.")
            ("help", "Print this usage information.")
            ("port", opts::value<uint16_t>(), "Port.")
            ;

        visible_desc.add(common_desc);

        opts::variables_map vm;
        opts::store(
            opts::command_line_parser(argc, argv)
                .options(visible_desc)
                .run(),
            vm);

        if (vm.count("config")) {
            fs::path path(vm["config"].as<std::string>());
            if (!fs::exists(path))
                ExitError(visible_desc, "configuration file does not exist");

            try {
                opts::store(opts::parse_config_file<char>(path.c_str(), visible_desc), vm);
            } catch (const std::exception& e) {
                ExitError(visible_desc, "unable to parse configuration file");
            }
        }

        opts::notify(vm);

        if (vm.count("port")) {
            conf.port_ = vm["port"].as<uint16_t>();
        }

        if (vm.count("help")) {
            std::cout << visible_desc;
            exit(0);
        }

        FLAGS_logtostderr = true;
    } catch (const std::exception& e) {
        std::stringstream msg;
        msg << "unable to process options -- " << e.what();
        ExitError(visible_desc, msg.str());
    }
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk) {
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        LOG(ERROR) << "unable to set read timeout";
        return false;
    }

    return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char* buf, const size_t n) {
    char* ptr = buf;
    while (ptr < buf + n) {
        if (!SetReadTimeout(sk)) {
            return false;
        }

        auto ret = recv(sk, ptr, ptr - buf + n, 0);
        if (ret <= 0) {
            LOG(ERROR) << "unable to receive on socket";
            return false;
        }

        ptr += ret;
    }

    return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char* buf, const size_t n) {
    auto ptr = buf;
    while (ptr < buf + n) {
        auto ret = send(sk, ptr, n - (ptr - buf), 0);
        if (ret <= 0) {
            LOG(ERROR) << "unable to send on socket";
            return false;
        }

        ptr += ret;
    }

    return true;
}

/**
 * Handle a client.
 *
 * @param sk Socket.
 */
static void OnClient(const int sk) {
    size_t len;
    char buf[1024];

    // Read the message length.
    if (!ReadBytes(sk, reinterpret_cast<char*>(&len), sizeof(len))) {
        LOG(ERROR) << "unable to read message length";
        return;
    }

    LOG(INFO) << "reading the message (" << len << " bytes" << ")";

    // Read the message.
    ReadBytes(sk, buf, len);

    LOG(INFO) << "echoing the message";

    // Echo the message.
    WriteBytes(sk, buf, len);
}

/**
 * Run the service.
 *
 * @param conf Configuration.
 */
static void RunService(Config& conf) {
    auto sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
        LOG(ERROR) << "unable to create server socket";
        LOG(ERROR) << strerror(errno);
        return;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(conf.port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    auto opt = 1;
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG(ERROR) << "unable to set REUSE_ADDR on server socket";
        LOG(ERROR) << strerror(errno);
        return;
    }

    if (bind(sk, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG(ERROR) << "unable to bind server socket";
        LOG(ERROR) << strerror(errno);
        return;
    }

    if (listen(sk, 16) < 0) {
        LOG(ERROR) << "unable to listen on server socket";
        LOG(ERROR) << strerror(errno);
        return;
    }

    while (true) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        memset(&client_addr, 0, sizeof(client_addr));
        auto client_sk =
            accept(
                sk,
                reinterpret_cast<sockaddr*>(&client_addr),
                &addr_len);
        if (client_sk < 0) {
            LOG(ERROR) << "unable to accept connection";
            LOG(ERROR) << strerror(errno);
            return;
        }

#ifdef DO_FORK
        pid_t child;
        switch (child = fork()) {
            case -1:
                LOG(ERROR) << "unable to fork client handler";
                LOG(ERROR) << strerror(errno);
                return;

            case 0:
#endif // DO_FORK
                OnClient(client_sk);
#ifdef DO_FORK
                exit(0);

            default:
#endif // DO_FORK
                close(client_sk);
#ifdef DO_FORK
                break;
        }

        while (true) {
            int st;
            if (waitpid(-1, &st, WNOHANG) < 0) {
                break;
            }
        }
#endif // DO_FORK
    }
}

/**
 * Main.
 */
int main(int argc, char** argv) {
    Config conf;
    ParseArgs(argc, argv, conf);
    google::InitGoogleLogging(argv[0]);
    RunService(conf);
    return 0;
}
