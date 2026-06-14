// license:BSD-3-Clause
// copyright-holders:R. Belmont, AJR
/***************************************************************************

    Tektronix 440x "AI Workstations"

    skeleton by R. Belmont

    Hardware overview:
        * 68010 (4404) or 68020 (4405) with custom MMU
        * Intelligent floppy subsystem with 6502 driving a uPD765 controller
        * NS32081 FPU
        * AMD LANCE Ethernet controller
        * 6551 debug console AICA
        * SN76496 PSG for sound
        * MC146818 RTC
        * MC68681 DUART / timer (3.6864 MHz clock) (serial channel A = keyboard, channel B = RS-232 port)
        * AM9513 timer (source of timer IRQ)
        * NCR5385 SCSI controller

		* X2210 NVRAM
        Video is a 640x480 1bpp window on a 1024x1024 VRAM area; smooth panning around that area
        is possible as is flat-out changing the scanout address.

    IRQ levels:
        7 = Debug (NMI)
        6 = VBL
        5 = UART
        4 = Spare (exp slots)
        3 = SCSI
        2 = DMA
        1 = Timer
        0 = Unused

    MMU info:
        Map control register (location unk): bit 15 = VM enable, bits 10-8 = process ID

        Map entries:
            bit 15 = dirty
            bit 14 = write enable
            bit 13-11 = process ID
            bits 10-0 = address bits 22-12 in the final address

***************************************************************************/

#include "emu.h"

#include "tek410x_kbd.h"
#include "tek_msu_fdc.h"

#include "bus/nscsi/hd.h"
#include "bus/rs232/rs232.h"
#include "cpu/m68000/m68010.h"
#include "machine/am79c90.h"
#include "machine/am9513.h"
#include "machine/bankdev.h"
#include "machine/input_merger.h"
#include "machine/mc146818.h"
#include "machine/mc68681.h"
#include "machine/mos6551.h"    // debug tty
#include "machine/ncr5385.h"
#include "machine/ns32081.h"
#include "machine/nscsi_bus.h"
#include "machine/x2212.h"
#include "sound/sn76496.h"

#include "emupal.h"
#include "screen.h"
#include "speaker.h"

#include "logmacro.h"

namespace {

class tek440x_state : public driver_device
{
public:
	tek440x_state(const machine_config &mconfig, device_type type, const char *tag) :
		driver_device(mconfig, type, tag),
		m_maincpu(*this, "maincpu"),
		m_vm(*this, "vm"),
		m_duart(*this, "duart"),
		m_keyboard(*this, "keyboard"),
		m_snsnd(*this, "snsnd"),
		m_timer(*this, "timer"),
		m_rtc(*this, "rtc"),
		m_scsi(*this, "ncr5385"),
		m_prom(*this, "maincpu"),
		m_screen(*this, "screen"),
		m_fpu(*this, "fpu"),
		m_lance(*this, "lance"),
		m_novram(*this, "novram"),
		m_mainram(*this, "mainram"),
		m_vram(*this, "vram"),
		m_map(*this, "map", 0x1000, ENDIANNESS_BIG),
		m_map_view(*this, "map"),
		m_boot(false),
		m_map_control(0),
		m_kb_rdata(true),
		m_kb_tdata(true),
		m_kb_rclamp(false),
		m_kb_loop(false)
	{ }

	void tek4404(machine_config &config);

private:
	virtual void machine_start() override ATTR_COLD;
	virtual void machine_reset() override ATTR_COLD;
	u32 screen_update(screen_device &screen, bitmap_ind16 &bitmap, const rectangle &cliprect);

	u16 memory_r(offs_t offset, u16 mem_mask);
	void memory_w(offs_t offset, u16 data, u16 mem_mask);
	u16 map_r(offs_t offset);
	void map_w(offs_t offset, u16 data, u16 mem_mask);
	u8 mapcntl_r();
	void mapcntl_w(u8 data);
	void sound_w(u8 data);
	void diag_w(u8 data);
	void fpu_finished(int v);
	u16 fpu_r(offs_t offset);
	void fpu_w(offs_t offset, u16 data);
	
	u16 videoaddr_r(offs_t offset);
	void videoaddr_w(offs_t offset, u16 data);
	u8 videocntl_r();
	void videocntl_w(u8 data);

	uint8_t nvram_r(offs_t offset);
	void nvram_w(offs_t offset, u8 data);
	uint8_t recall_r();
	void recall_w(uint8_t data);
	uint8_t store_r();
	void store_w(uint8_t data);

	void palette(palette_device &palette) const;

	// need to handle bit 8 reset
	void timer_irq(int state);
	u16 timer_r(offs_t offset);
	void timer_w(offs_t offset, u16 data);


	void kb_rdata_w(int state);
	void kb_tdata_w(int state);
	void kb_rclamp_w(int state);

	void logical_map(address_map &map) ATTR_COLD;
	void physical_map(address_map &map) ATTR_COLD;

	required_device<m68010_device> m_maincpu;
	required_device<address_map_bank_device> m_vm;
	required_device<mc68681_device> m_duart;
	required_device<tek410x_keyboard_device> m_keyboard;
	required_device<sn76496_device> m_snsnd;
	required_device<am9513_device> m_timer;
	required_device<mc146818_device> m_rtc;
	required_device<ncr5385_device> m_scsi;
	required_device<screen_device> m_screen;
	required_device<mos6551_device> m_acia;
	required_device<ns32081_device> m_fpu;
	required_device<am7990_device> m_lance;
	required_device<x2210_device> m_novram;

	required_region_ptr<u16> m_prom;
	required_shared_ptr<u16> m_mainram;
	required_shared_ptr<u16> m_vram;
	memory_share_creator<u16> m_map;
	memory_view m_map_view;


	int m_u244latch;
	
	bool m_boot;
	u8 m_map_control;
	u8 m_vint_enable;				// VIntEn also used to hold U4438 in reset state
	
	bool m_kb_rdata;
	bool m_kb_tdata;
	bool m_kb_rclamp;
	bool m_kb_loop;
	u16 m_videoaddr;
	u8 m_videocntl;
};

/*************************************
 *
 *  Machine start
 *
 *************************************/

void tek440x_state::machine_start()
{
	save_item(NAME(m_boot));
	save_item(NAME(m_map_control));
	save_item(NAME(m_kb_rdata));
	save_item(NAME(m_kb_tdata));
	save_item(NAME(m_kb_rclamp));
	save_item(NAME(m_kb_loop));
}



/*************************************
 *
 *  Machine reset
 *
 *************************************/

void tek440x_state::machine_reset()
{
	m_boot = true;
	diag_w(0);
	m_u244latch = 0;
	m_keyboard->kdo_w(1);
	mapcntl_w(0);
	videocntl_w(0);

	m_vint_enable = 0;
	
	m_novram->recall(ASSERT_LINE);
	m_novram->recall(CLEAR_LINE);

/*************************************
 *
 *  Video refresh
 *
 *************************************/

u32 tek440x_state::screen_update(screen_device &screen, bitmap_ind16 &bitmap, const rectangle &cliprect)
{
	if (!BIT(m_videocntl, 5))
	{
		// screen off
		bitmap.fill((uint16_t)0xffff, cliprect);
		return 0;
	}

	u32 invert = BIT(m_videocntl, 4) ? 0 : -1;
	int pan = (m_videocntl & 15) ^ 15;

	u16 woffset = (m_videoaddr - (0xffe9));  // why 0xffe9 is TL..OS uses same magic number
	
	//LOG("screen_update: 0x%04x\n", woffset);
	for (int y = 0; y < 480; y++)
	{
	
		u16 *const line = &bitmap.pix(y);
		u16 const *video_ram = &m_vram[y * 64 + woffset];

		for (int x = 0; x < 640; x += 16)
		{
			u16 const word = *(video_ram++);
			u16 const word2 = *(video_ram);
			u32 dword = ((word << 16) | word2) ^ invert;
			for (int b = 0; b < 16; b++)
			{
				line[x + b] = BIT(dword, 31 - pan - b);
			}
		}
	}

	return 0;
}



/*************************************
 *
 *  CPU memory handlers
 *
 *************************************/

u16 tek440x_state::memory_r(offs_t offset, u16 mem_mask)
{
	if (m_boot)
		return m_prom[offset & 0x3fff];

	const offs_t offset0 = offset;
	if (BIT(m_map_control, 4))
		offset = BIT(offset, 0, 11) | BIT(m_map[offset >> 11], 0, 11) << 11;
	if (offset < 0x300000 && offset >= 0x100000 && !machine().side_effects_disabled())
	{
		m_maincpu->set_input_line(M68K_LINE_BUSERROR, ASSERT_LINE);
		m_maincpu->set_input_line(M68K_LINE_BUSERROR, CLEAR_LINE);
		m_maincpu->set_buserror_details(offset0 << 1, 1, m_maincpu->get_fc());
	}

	return m_vm->read16(offset, mem_mask);
}

void tek440x_state::memory_w(offs_t offset, u16 data, u16 mem_mask)
{
	const offs_t offset0 = offset;
	if (BIT(m_map_control, 4))
		offset = BIT(offset, 0, 11) | BIT(m_map[offset >> 11], 0, 11) << 11;
	if (offset < 0x300000 && offset >= 0x100000 && !machine().side_effects_disabled())
	{
		m_maincpu->set_input_line(M68K_LINE_BUSERROR, ASSERT_LINE);
		m_maincpu->set_input_line(M68K_LINE_BUSERROR, CLEAR_LINE);
		m_maincpu->set_buserror_details(offset0 << 1, 0, m_maincpu->get_fc());
	}

	m_vm->write16(offset, data, mem_mask);
}

u16 tek440x_state::map_r(offs_t offset)
{
	return m_map[offset >> 11];
}

void tek440x_state::map_w(offs_t offset, u16 data, u16 mem_mask)
{
	COMBINE_DATA(&m_map[offset >> 11]);
}

u8 tek440x_state::mapcntl_r()
{
	return m_map_control;
}

void tek440x_state::mapcntl_w(u8 data)
{
	if (BIT(data, 5))
		m_map_view.select(0);
void tek440x_state::fpu_finished(int val)
{

	// active low
	if (val == 0)
	{
		LOGMASKED(LOG_FPU, "fpu_finished\n");
		m_fpu_finished = 1;
	}
}

void tek440x_state::fpu_w(offs_t offset, u16 data)
{
	//LOGMASKED(LOG_FPU,"fpu_w:  %08x <= 0x%04x\n", offset, data);

	// page 2.1-72  AD.02,AD.03 drive ST0,ST1 of 32081
	switch(offset)
	{
		default:
			break;
		
		// latches opcode.w, arg1.l, arg2.l
		case 2:
		case 3:
			m_fpu->slow_write(data);
			break;

		// broadcast slave id  (0xbe or 0x3e)
		case 6:
			LOGMASKED(LOG_FPU,"fpu_w: broadcast slave 0x%04x\n", data);
			m_fpu_finished = 0;
			m_fpu->slow_write(data);
			break;
		case 7:
			break;
	}
}

u16 tek440x_state::fpu_r(offs_t offset)
{

	u16 result = 0;
	switch(offset)
	{
		default:
			break;

		case 2:
		case 3:
			result = m_fpu->slow_read();
			break;

		case 4:
			if (m_fpu_finished)
			{
				result = m_fpu->slow_status();
				LOGMASKED(LOG_FPU,"fpu_r: status = 0x%04x\n", result);
			}
			else
			{
				LOGMASKED(LOG_FPU,"fpu_r: status = BUSY\n");
				
				// page 2.1.72   FPC.pal:   IF (/Wr*FPSel) /D.15 = /FP.15*/Busy
				result = 0x8000;
			}
			break;
	}
	
	return result;
}

u16 tek440x_state::videoaddr_r(offs_t offset)
{
	//LOG("videoaddr_r %08x\n", offset);
	return m_videoaddr;
}

void tek440x_state::videoaddr_w(offs_t offset, u16 data)
{
	//LOG("videoaddr_w %08x <= %04x\n", offset, data);
	m_videoaddr = data;
}

u8 tek440x_state::videocntl_r()
{
	int ans = m_videocntl;

	// page 2.1-92
	if (m_screen->vblank())
		ans |= 0x20;
	else
		ans |= 0x10;		// should be VAD.04; this allows VIDEO_selftest to pass
		
	if (m_screen->hblank())
		ans |= 0x40;
		
	// SoundRdy
	ans |= m_soundrdy;
		
	return ans;
}

void tek440x_state::videocntl_w(u8 data)
{

#if 0
	if (m_videocntl != data)
	{
		LOG("m_videocntl %02x\n", data);
		LOG("m_videocntl VBenable   %2d\n", BIT(data, 6));
		LOG("m_videocntl ScreenOn   %2d\n", BIT(data, 5));
		LOG("m_videocntl ScreenInv  %2d\n", BIT(data, 4));
		LOG("m_videocntl ScreenPan  %2d\n", data & 15);
	}
#endif

	m_vint_enable = BIT(data, 6);
	if (!m_vint_enable)
	{
		// VIntEn resets U4438 pulling VSyncInt high
		m_maincpu->set_input_line(M68K_IRQ_6, CLEAR_LINE);
	}
	
	m_videocntl = data;
}

void tek440x_state::sound_w(u8 data)
{
	m_snsnd->write(data);
	m_boot = false;
}

void tek440x_state::diag_w(u8 data)
{
	if (!m_kb_rclamp && m_kb_loop != BIT(data, 7))
		m_keyboard->kdo_w(!BIT(data, 7) || m_kb_tdata);

	m_kb_loop = BIT(data, 7);
}

void tek440x_state::kb_rdata_w(int state)
{
	m_kb_rdata = state;
	if (!m_kb_rclamp)
		m_duart->rx_a_w(state);
}

void tek440x_state::kb_rclamp_w(int state)
{
	if (m_kb_rclamp != !state)
	{
		m_kb_rclamp = !state;

		// Clamp RXDA to 1 and KBRDATA to 0 when DUART asserts RxRDYA
		if (m_kb_tdata || !m_kb_loop)
			m_keyboard->kdo_w(state);
		m_duart->rx_a_w(state ? m_kb_rdata : 1);
	}
}

void tek440x_state::kb_tdata_w(int state)
{
	if (m_kb_tdata != state)
	{
		m_kb_tdata = state;

		m_duart->ip4_w(!state);
		if (m_kb_loop && m_kb_rdata && !m_kb_rclamp)
			m_keyboard->kdo_w(state);
	}
}

void tek440x_state::timer_irq(int state)
{
	LOGMASKED(LOG_IRQ,"%10s: irq1_raise %04x\n", machine().time().as_string(8), state);
	
	if (state == 0)
	{
		//LOG("M68K_IRQ_1 assert\n");
		m_maincpu->set_input_line(M68K_IRQ_1, ASSERT_LINE);

		m_u244latch = 1;
	}
	else
	{
		m_maincpu->set_input_line(M68K_IRQ_1, CLEAR_LINE);	
	}
}

// to handle offset 0x1xx reads resetting TPInt...
u16 tek440x_state::timer_r(offs_t offset)
{
	LOGMASKED(LOG_IRQ,"%10s: timer_r %08x pc(%08x)\n", machine().time().as_string(8), offset, m_maincpu->pc());

	//if (m_u244latch)
	{
		LOGMASKED(LOG_IRQ,"timer_r: M68K_IRQ_1 clear\n");
		m_maincpu->set_input_line(M68K_IRQ_1, CLEAR_LINE);
		m_u244latch = 0;
	}

	return m_timer->read16(offset);
}

// to handle offset 0x1xx writes resetting TPInt...
void tek440x_state::timer_w(offs_t offset, u16 data)
{
	//LOG("timer_w %08x %04x pc(%08x)\n", OFF16_TO_OFF8(offset), data, m_maincpu->pc());
	m_timer->write16(offset, data);

	//if (m_u244latch)
	{
		LOGMASKED(LOG_IRQ,"timer_w: M68K_IRQ_1 clear\n");
		m_maincpu->set_input_line(M68K_IRQ_1, CLEAR_LINE);
		m_u244latch = 0;
	}
}

uint8_t tek440x_state::nvram_r(offs_t offset)
{
	u8 data = m_novram->read(m_maincpu->space(0), offset);

	LOG("nvram_r(%d) => %02x pc(%08x)\n",offset, data, m_maincpu->pc());

	// kick it up to top 4 bits
	return data << 4;
}
void tek440x_state::nvram_w(offs_t offset, u8 data)
{
	LOG("nvram_w(%d) <= %02x\n",offset, data);

	// duplicate in lower 4 bits
	m_novram->write(offset, data | (data >> 4));
}
	
uint8_t tek440x_state::recall_r()
{
	LOG("recall_r\n");
	if (!machine().side_effects_disabled())
	{
		m_novram->recall(1);
		m_novram->recall(0);
	}

	return 0xff;
}

void tek440x_state::recall_w(uint8_t data)
{
	LOG("recall_w\n");
	m_novram->recall(1);
	m_novram->recall(0);
}

uint8_t tek440x_state::store_r()
{
	LOG("store_r\n");
	if (!machine().side_effects_disabled())
	{
		m_novram->store(1);
		m_novram->store(0);
	}

	return 0xff;
}

void tek440x_state::store_w(uint8_t data)
{
	LOG("store_w\n");
	m_novram->store(1);
	m_novram->store(0);
}

void tek440x_state::palette(palette_device &palette) const
{
	palette.set_pen_color(0, rgb_t(0xec, 0xf4, 0xff));   // 2 color framebuffer
	palette.set_pen_color(1, rgb_t(0x00, 0x00, 0x00));
}


void tek440x_state::logical_map(address_map &map)
{
	map(0x000000, 0x7fffff).rw(FUNC(tek440x_state::memory_r), FUNC(tek440x_state::memory_w));
	map(0x800000, 0xffffff).view(m_map_view);
	m_map_view[0](0x800000, 0xffffff).rw(FUNC(tek440x_state::map_r), FUNC(tek440x_state::map_w));
}

void tek440x_state::physical_map(address_map &map)
{
	map(0x000000, 0x1fffff).ram().share("mainram");
	map(0x600000, 0x61ffff).ram().share("vram");

	// 700000-71ffff spare 0
	// 720000-73ffff spare 1
	map(0x740000, 0x747fff).rom().mirror(0x8000).region("maincpu", 0);
	// 720000-720fff spare 1 (ethernet)
	map(0x720000, 0x720007).rw(m_lance, FUNC(am79c90_device::regs_r), FUNC(am79c90_device::regs_w));

	// 721000-72107f net ram
	// 722000-721fff nvram nybbles
	map(0x721000, 0x7210ff).rw(FUNC(tek440x_state::nvram_r), FUNC(tek440x_state::nvram_w));
	map(0x722000, 0x722fff).rw(FUNC(tek440x_state::recall_r), FUNC(tek440x_state::recall_w));
	map(0x723000, 0x723fff).rw(FUNC(tek440x_state::store_r), FUNC(tek440x_state::store_w));
	
	map(0x760000, 0x760fff).ram().mirror(0xf000); // debug RAM

	// 780000-79ffff processor board I/O
	map(0x780000, 0x780000).rw(FUNC(tek440x_state::mapcntl_r), FUNC(tek440x_state::mapcntl_w));
	// 782000-783fff: video address registers
	map(0x782000, 0x782003).rw(FUNC(tek440x_state::videoaddr_r),FUNC(tek440x_state::videoaddr_w));
	// 784000-785fff: video control registers
	map(0x784000, 0x784000).rw(FUNC(tek440x_state::videocntl_r),FUNC(tek440x_state::videocntl_w));
	// 786000-787fff: spare
	map(0x788000, 0x788000).w(FUNC(tek440x_state::sound_w));
	map(0x78a000, 0x78bfff).rw(FUNC(tek440x_state::fpu_r),FUNC(tek440x_state::fpu_w));
	map(0x78c000, 0x78c007).rw(m_acia, FUNC(mos6551_device::read), FUNC(mos6551_device::write)).umask16(0xff00);
	// 78e000-78ffff: spare

	// 7a0000-7bffff peripheral board I/O
	// 7a0000-7affff: reserved
	map(0x7b0000, 0x7b0000).w(FUNC(tek440x_state::diag_w));
	// 7b1000-7b1fff: diagnostic registers
	// 7b2000-7b3fff: Centronics printer data
	map(0x7b4000, 0x7b401f).rw(m_duart, FUNC(mc68681_device::read), FUNC(mc68681_device::write)).umask16(0xff00);
	// 7b6000-7b7fff: Mouse
	map(0x7b8000, 0x7b8003).mirror(0x100).rw("timer", FUNC(am9513_device::read16), FUNC(am9513_device::write16));

	map(0x7b8000, 0x7b8003).rw(m_timer, FUNC(am9513_device::read16), FUNC(am9513_device::write16));
	map(0x7b8100, 0x7b8103).rw(FUNC(tek440x_state::timer_r), FUNC(tek440x_state::timer_w));
	
	// 7ba000-7bbfff: MC146818 RTC
	map(0x7ba000, 0x7ba03f).rw(m_rtc, FUNC(mc146818_device::read_direct), FUNC(mc146818_device::write_direct));

	
	map(0x7bc000, 0x7bc000).lw8(
		[this](u8 data)
		{
			m_scsi->set_own_id(data & 7);

			// TODO: bit 7 -> SCSI bus reset
			LOG("scsi bus reset %d\n", BIT(data, 7));
		}, "scsi_addr"); // 7bc000-7bdfff: SCSI bus address registers
	map(0x7be000, 0x7be01f).m(m_scsi, FUNC(ncr5385_device::map)).umask16(0xff00); //.mirror(0x1fe0) .cswidth(16);

	// 7c0000-7fffff EPROM application space
	map(0x7c0000, 0x7fffff).nopr();
}

/*************************************
 *
 *  Port definitions
 *
 *************************************/

static INPUT_PORTS_START( tek4404 )
INPUT_PORTS_END

/*************************************
 *
 *  Machine driver
 *
 *************************************/

static void scsi_devices(device_slot_interface &device)
{
	device.option_add("harddisk", NSCSI_HARDDISK);
	device.option_add("tek_msu_fdc", TEK_MSU_FDC);
}

// interrupts
// 7 debug
// 6 vsync
// 5 uart
// 4 spare
// 3 scsi
// 2 dma (network?)
// 1 timer/printer

void tek440x_state::tek4404(machine_config &config)
{
	/* basic machine hardware */
	M68010(config, m_maincpu, 40_MHz_XTAL / 4); // MC68010L10
	m_maincpu->set_addrmap(AS_PROGRAM, &tek440x_state::logical_map);

	ADDRESS_MAP_BANK(config, m_vm);
	m_vm->set_addrmap(0, &tek440x_state::physical_map);
	m_vm->set_data_width(16);
	m_vm->set_addr_width(23);
	m_vm->set_endianness(ENDIANNESS_BIG);

	/* video hardware */
	SCREEN(config, m_screen, SCREEN_TYPE_RASTER);
	m_screen->set_video_attributes(VIDEO_UPDATE_BEFORE_VBLANK);
	m_screen->set_raw(25.2_MHz_XTAL, 800, 0, 640, 525, 0, 480); // 31.5 kHz horizontal (guessed), 60 Hz vertical
	m_screen->set_screen_update(FUNC(tek440x_state::screen_update));
	m_screen->set_palette("palette");
	m_screen->screen_vblank().set([this](int state)
    {
		LOGMASKED(LOG_IRQ,"%10s: vblank(%d) vint(%d)\n", machine().time().as_string(8), state,m_vint_enable);
		if (state && m_vint_enable)
		{
			m_maincpu->set_input_line(M68K_IRQ_6, ASSERT_LINE);
		}
    });
	PALETTE(config, "palette", FUNC(tek440x_state::palette),2);
	
	MOS6551(config, m_acia, 40_MHz_XTAL / 4 / 10);
	m_acia->set_xtal(1.8432_MHz_XTAL);
	m_acia->txd_handler().set("rs232", FUNC(rs232_port_device::write_txd));
	m_acia->irq_handler().set_inputline(m_maincpu, M68K_IRQ_7);

	NS32081(config, m_fpu, 20_MHz_XTAL / 2);
	m_fpu->out_spc().set(FUNC(tek440x_state::fpu_finished));

	// ethernet
	AM7990(config, m_lance, 40_MHz_XTAL / 4);
	m_lance->intr_out().set_inputline(m_maincpu, M68K_IRQ_2).invert();
	
	
	m_lance->dma_in().set([this](offs_t offset) {
		u16 data = m_vm->read16(OFF8_TO_OFF16(offset));
		//LOG("dma_in 0x%08x => %04x\n",offset,data);
		return data;
	});
	m_lance->dma_out().set([this](offs_t offset, u16 data, u16 mem_mask) {
		//LOG("dma_out 0x%08x <= %04x\n",offset, data);
		return m_vm->write16(OFF8_TO_OFF16(offset),data, mem_mask);
	});

	X2210(config, m_novram);

	MC68681(config, m_duart, 14.7456_MHz_XTAL / 4);
	m_duart->irq_cb().set_inputline(m_maincpu, M68K_IRQ_5); // auto-vectored
	m_duart->outport_cb().set(FUNC(tek440x_state::kb_rclamp_w)).bit(4);
	m_duart->outport_cb().append(m_keyboard, FUNC(tek410x_keyboard_device::reset_w)).bit(3);
	m_duart->a_tx_cb().set(m_keyboard, FUNC(tek410x_keyboard_device::kdi_w));

	TEK410X_KEYBOARD(config, m_keyboard);
	m_keyboard->tdata_callback().set(FUNC(tek440x_state::kb_tdata_w));
	m_keyboard->rdata_callback().set(FUNC(tek440x_state::kb_rdata_w));

	AM9513(config, m_timer, 40_MHz_XTAL / 4 / 10 ); // from CPU E output

	// see diagram page 2.2-6
	INPUT_MERGER_ALL_HIGH(config, "irq1").output_handler().set(FUNC(tek440x_state::timer_irq));
	m_timer->out1_cb().set("irq1", FUNC(input_merger_device::in_w<0>));
	m_timer->out2_cb().set("irq1", FUNC(input_merger_device::in_w<1>));

	MC146818(config, m_rtc, 32.768_kHz_XTAL);

	auto &scsi(NSCSI_BUS(config, "scsi"));
	// hard disk is a Micropolis 1304 (https://www.micropolis.com/support/hard-drives/1304)
	// with a Xebec 1401 SASI adapter inside the Mass Storage Unit
	NSCSI_CONNECTOR(config, "scsi:0", scsi_devices, "harddisk");
	NSCSI_CONNECTOR(config, "scsi:1", scsi_devices, "tek_msu_fdc");
	NSCSI_CONNECTOR(config, "scsi:2", scsi_devices, nullptr);
	NSCSI_CONNECTOR(config, "scsi:3", scsi_devices, nullptr);
	NSCSI_CONNECTOR(config, "scsi:4", scsi_devices, nullptr);
	NSCSI_CONNECTOR(config, "scsi:5", scsi_devices, nullptr);
	NSCSI_CONNECTOR(config, "scsi:6", scsi_devices, nullptr);

	NCR5385(config, m_scsi, 40_MHz_XTAL / 4);
	scsi.set_external_device(7, m_scsi);
	m_scsi->irq().set_inputline(m_maincpu, M68K_IRQ_3);

	rs232_port_device &rs232(RS232_PORT(config, "rs232", default_rs232_devices, nullptr));
	rs232.rxd_handler().set(m_acia, FUNC(mos6551_device::write_rxd));
	rs232.dcd_handler().set(m_acia, FUNC(mos6551_device::write_dcd));
	rs232.dsr_handler().set(m_acia, FUNC(mos6551_device::write_dsr));
	rs232.cts_handler().set(m_acia, FUNC(mos6551_device::write_cts));

	SPEAKER(config, "mono").front_center();

	SN76496(config, m_snsnd, 25.2_MHz_XTAL / 8).add_route(ALL_OUTPUTS, "mono", 0.80);
}



/*************************************
 *
 *  ROM definition(s)
 *
 *************************************/

ROM_START( tek4404 )
	ROM_REGION( 0x8000, "maincpu", 0 )
	ROM_LOAD16_BYTE( "tek_u158.bin", 0x000000, 0x004000, CRC(9939e660) SHA1(66b4309e93e4ff20c1295dc2ec2a8d6389b2578c) )
	ROM_LOAD16_BYTE( "tek_u163.bin", 0x000001, 0x004000, CRC(a82dcbb1) SHA1(a7e4545e9ea57619faacc1556fa346b18f870084) )

	ROM_REGION( 0x2000, "scsimfm", 0 )
	ROM_LOAD( "scsi_mfm.bin", 0x000000, 0x002000, CRC(b4293435) SHA1(5e2b96c19c4f5c63a5afa2de504d29fe64a4c908) )
ROM_END

} // anonymous namespace


/*************************************
 *
 *  Game driver(s)
 *
 *************************************/
//    YEAR  NAME     PARENT  COMPAT  MACHINE  INPUT    CLASS          INIT        COMPANY      FULLNAME                               FLAGS
COMP( 1984, tek4404, 0,      0,      tek4404, tek4404, tek440x_state, empty_init, "Tektronix", "4404 Artificial Intelligence System", MACHINE_NOT_WORKING )
