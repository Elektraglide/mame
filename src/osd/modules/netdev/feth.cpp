// license:BSD-3-Clause
// copyright-holders:Carl
#include "netdev_module.h"

#include "modules/osdmodule.h"

#define OSD_NET_USE_FETH

#if defined(OSD_NET_USE_FETH)

#include "netdev_common.h"

#include "osdcore.h" // osd_printf_verbose
#include "osdfile.h" // PATH_SEPARATOR

#include "util/hashing.h" // crc32_creator
#include "util/unicode.h"

#include <memory>
#include <vector>


#if defined(__APPLE__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

constexpr unsigned int UDP_PORT = 9999;
constexpr unsigned int BUFFER_SIZE = 2048;

namespace osd {

namespace {

// Ethernet minimum frame length
static constexpr int ETHERNET_MIN_FRAME = 64;

class feth_module : public osd_module, public netdev_module
{
public:

	feth_module() : osd_module(OSD_NETDEV_PROVIDER, "feth"), netdev_module()
	{
	}
	virtual ~feth_module() { }

	virtual int init(osd_interface &osd, const osd_options &options) override;
	virtual void exit() override;

	virtual bool probe() override { return true; }

	virtual std::unique_ptr<network_device> open_device(int id, network_handler &handler) override;
	virtual std::vector<network_device_info> list_devices() override;

private:
	struct device_info
	{
		std::string name;
		std::string description;
	};

	std::vector<device_info> m_devices;
};



class netdev_feth : public network_device_base
{
public:
	netdev_feth(const char *name, network_handler &handler);
	~netdev_feth();

	int send(void const *buf, int len) override;

protected:
	int recv_dev(uint8_t **buf) override;

private:
	int m_fd = -1;
    struct sockaddr_in m_daemon_addr;
	uint8_t m_buf[BUFFER_SIZE];
};

netdev_feth::netdev_feth(const char *name, network_handler &handler)
	: network_device_base(handler)
{
	m_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (m_fd >= 0) {
		// Set socket non-blocking to prevent freezing the MAME emulation loop
		fcntl(m_fd, F_SETFL, O_NONBLOCK);
		
		m_daemon_addr.sin_family = AF_INET;
		m_daemon_addr.sin_port = htons(UDP_PORT); // Privileged daemon port
		m_daemon_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

		osd_printf_info("feth: up\n");
	}
        
}

netdev_feth::~netdev_feth()
{
	close(m_fd);
}

static u32 finalise_frame(u8 buf[], u32 length)
{
	/*
	 * The feth driver receives frames which are shorter than the Ethernet
	 * minimum. Partly this is because it can't see the frame check sequence
	 * bytes, but mainly it's because the OS expects the lower level device
	 * to add the required padding.
	 *
	 * We do the equivalent padding here (i.e. pad with zeroes to the
	 * minimum Ethernet length minus FCS), so that devices which check
	 * for this will not reject these packets.
	 */
	if (length < ETHERNET_MIN_FRAME - 4)
	{
		std::fill_n(&buf[length], ETHERNET_MIN_FRAME - length - 4, 0);

		length = ETHERNET_MIN_FRAME - 4;
	}

	// compute and append the frame check sequence
	const u32 fcs = util::crc32_creator::simple(buf, length);

	buf[length++] = (fcs >> 0) & 0xff;
	buf[length++] = (fcs >> 8) & 0xff;
	buf[length++] = (fcs >> 16) & 0xff;
	buf[length++] = (fcs >> 24) & 0xff;

	return length;
}


int netdev_feth::send(void const *buf, int len)
{
	if(m_fd == -1) return 0;
	osd_printf_info(" netdev_feth::send(%d)\n", len);
	len = sendto(m_fd, buf, len, 0, (struct sockaddr*)&m_daemon_addr, sizeof(m_daemon_addr));
	return (len == -1) ? 0 : len;
}

int netdev_feth::recv_dev(uint8_t **buf)
{
	if (0 > m_fd)
		return 0;

	struct sockaddr_in from_addr;
	socklen_t from_len = sizeof(from_addr);
	
	// Non-blocking read of frames received from the daemon
	int bytes_received = recvfrom(m_fd, m_buf, BUFFER_SIZE, 0, (struct sockaddr*)&from_addr, &from_len);
	if (bytes_received < 0) {
		return 0; // No packets waiting in the UDP socket queue
	}

	if (bytes_received > 0)
	{
		bytes_received = finalise_frame(m_buf, bytes_received);
		osd_printf_info(" netdev_feth::recv_dev(%d)\n", bytes_received);

		*buf = m_buf;
	}

	return bytes_received;
}

int feth_module::init(osd_interface &osd, const osd_options &options)
{
	m_devices.emplace_back(device_info{ "feth", "Fake Ethernet Device" });
	return 0;
}

void feth_module::exit()
{
	m_devices.clear();
}

std::unique_ptr<network_device> feth_module::open_device(int id, network_handler &handler)
{
	if ((0 > id) || (m_devices.size() <= id))
		return nullptr;

	return std::make_unique<netdev_feth>(m_devices[id].name.c_str(), handler);
}

std::vector<network_device_info> feth_module::list_devices()
{
	std::vector<network_device_info> result;
	result.reserve(m_devices.size());
	for (int id = 0; m_devices.size() > id; ++id)
		result.emplace_back(network_device_info{ id, m_devices[id].description });
	return result;
}

} // anonymous namespace

} // namespace osd


#else

namespace osd { namespace { MODULE_NOT_SUPPORTED(feth_module, OSD_NETDEV_PROVIDER, "feth") } }

#endif


MODULE_DEFINITION(NETDEV_FETH, osd::feth_module)
