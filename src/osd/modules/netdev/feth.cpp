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
#include <unistd.h>
#include <fcntl.h>
#endif

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

	uint8_t m_buf[2048];
};

netdev_feth::netdev_feth(const char *name, network_handler &handler)
	: network_device_base(handler)
{
	m_fd = -1;
	if((m_fd = open("/dev/feth0", O_RDWR)) == -1) {
		osd_printf_verbose("feth: open failed %d\n", errno);
		return;
	}
	osd_printf_info("feth: up\n");
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
	len = write(m_fd, buf, len);
	return (len == -1)?0:len;
}

int netdev_feth::recv_dev(uint8_t **buf)
{
	if (0 > m_fd)
		return 0;

	int len = read(m_fd, m_buf, sizeof(m_buf));
	osd_printf_info(" netdev_feth::recv_dev(%d)\n", len);

	if (len > 0)
		len = finalise_frame(m_buf, len);

	*buf = m_buf;
	return (len == -1) ? 0 : len;
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
