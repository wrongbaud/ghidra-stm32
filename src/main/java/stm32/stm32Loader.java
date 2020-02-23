/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package stm32;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class stm32Loader extends AbstractLibrarySupportLoader {

	private static class RegLabel {
		String label;
		int addr;
		private RegLabel(String label, int addr) {
			this.label = label;
			this.addr = addr;
		}
		
	}
	
	private static final RegLabel [] USBFSRegs = {
			new RegLabel("OTG_FS_GOTGCTL",0x0),
			new RegLabel("OTG_FS_GOTGINT",0x4),
			new RegLabel("OTG_FS_GAHBCFG",0x8),
			new RegLabel("OTG_FS_GUSBCFG",0xc),
			new RegLabel("OTG_FS_GRSTCTL",0x10),
			new RegLabel("OTG_FS_GINTSTS",0x14),
			new RegLabel("OTG_FS_GINTMSK",0x18),
			new RegLabel("OTG_FS_GRXSTSR",0x1c),
			new RegLabel("OTG_FS_GRXSTSP",0x20),
			new RegLabel("OTG_FS_GRXFSIZ",0x24),
			new RegLabel("OTG_FS_HNPTXFSIZ",0x28),
			new RegLabel("OTG_FS_HNPTXSTS",0x2c),
			new RegLabel("OTG_FS_GCCFG",0x38),
			new RegLabel("OTG_FS_CID",0x3c),
			new RegLabel("OTG_FS_HPTIZ",0x100),
			new RegLabel("OTG_FS_DIEPTXF1",0x104),
			new RegLabel("OTG_FS_DIEPTXF2",0x108),
			new RegLabel("OTG_FS_DIEPTXF3",0x10c),
			new RegLabel("OTG_FS_HCFG",0x400),
			new RegLabel("OTG_FS_HFIR",0x404),
			new RegLabel("OTG_FS_HFNUM",0x408),
			new RegLabel("OTG_FS_HPTXSTS",0x410),
			new RegLabel("OTG_FS_HAINT",0x414),
			new RegLabel("OTG_FS_HAINTMSK",0x418),
            new RegLabel("OTG_FS_HPRT", 0x440),
            new RegLabel("OTG_FS_HCINTx", 0x508),
            new RegLabel("OTG_FS_HCINTMSKx", 0x50C),
            new RegLabel("OTG_FS_HCTSIZx", 0x510),
            new RegLabel("OTG_FS_DCFG", 0x800),
            new RegLabel("OTG_FS_DCTL", 0x804),
            new RegLabel("OTG_FS_DSTS", 0x808),
            new RegLabel("OTG_FS_DIEPMSK", 0x810),
            new RegLabel("OTG_FS_DOEPMSK", 0x814),
            new RegLabel("OTG_FS_DAINT", 0x818),
            new RegLabel("OTG_FS_DAINTMSK", 0x81C),
            new RegLabel("OTG_FS_DVBUSDIS", 0x828),
            new RegLabel("OTG_FS_DVBUSPULSE", 0x82C),
            new RegLabel("OTG_FS_DIEPEMPMSK", 0x834),
            new RegLabel("OTG_FS_DIEPCTL0", 0x900),
            new RegLabel("OTG_FS_DIEPINTx", 0x908),
            new RegLabel("OTG_FS_DIEPTSIZ0", 0x910),
            new RegLabel("OTG_FS_DIEPTSIZ1", 0x930),
            new RegLabel("OTG_FS_DIEPTSIZ1", 0x950),
            new RegLabel("OTG_FS_DIEPTSIZ1", 0x970),
            new RegLabel("OTG_FS_DOEPCTL0", 0xB00),
            new RegLabel("OTG_FS_DOEPCTL1", 0xB20),
            new RegLabel("OTG_FS_DOEPCTL2", 0xB40),
            new RegLabel("OTG_FS_DOEPCTL3", 0xB60),
            new RegLabel("OTG_FS_DOEPINT", 0xB08),
            new RegLabel("OTG_FS_DOEPTSIZ",0xB10),
	};

	private static final RegLabel [] USBHSRegs = {
			new RegLabel("OTG_HS_GOTGCTL",0x0),
			new RegLabel("OTG_HS_GOTGINT",0x4),
			new RegLabel("OTG_HS_GAHBCFG",0x8),
			new RegLabel("OTG_HS_GUSBCFG",0xc),
			new RegLabel("OTG_HS_GRSTCTL",0x10),
			new RegLabel("OTG_HS_GINTSTS",0x14),
			new RegLabel("OTG_HS_GINTMSK",0x18),
			new RegLabel("OTG_HS_GRXSTSR",0x1c),
			new RegLabel("OTG_HS_GRXSTSP",0x20),
			new RegLabel("OTG_HS_GRXFSIZ",0x24),
			new RegLabel("OTG_HS_HNPTXFSIZ",0x28),
			new RegLabel("OTG_HS_HNPTXSTS",0x2c),
			new RegLabel("OTG_HS_GCCFG",0x38),
			new RegLabel("OTG_HS_CID",0x3c),
			new RegLabel("OTG_HS_HPTIZ",0x100),
			new RegLabel("OTG_HS_DIEPTXF1",0x104),
			new RegLabel("OTG_HS_DIEPTXF2",0x108),
			new RegLabel("OTG_HS_DIEPTXF3",0x10C),
            new RegLabel("OTG_HS_DIEPTXF5",0x110),
            new RegLabel("OTG_HS_DIEPTXF6",0x114),
            new RegLabel("OTG_HS_DIEPTXF7",0x118),
			new RegLabel("OTG_HS_HCFG",0x400),
			new RegLabel("OTG_HS_HFIR",0x404),
			new RegLabel("OTG_HS_HFNUM",0x408),
			new RegLabel("OTG_HS_HPTXSTS",0x410),
			new RegLabel("OTG_HS_HAINT",0x414),
			new RegLabel("OTG_HS_HAINTMSK",0x418),
            new RegLabel("OTG_HS_HPRT", 0x440),
            new RegLabel("OTG_HS_HCSPLT", 0x504),
            new RegLabel("OTG_HS_HCINT", 0x508),
            new RegLabel("OTG_HS_HCINTMSK", 0x50C),
            new RegLabel("OTG_HS_HCTSIZx", 0x510),
            new RegLabel("OTG_HS_HCDMA", 0x514),
            new RegLabel("OTG_HS_HCCHAR0", 0x500),
            new RegLabel("OTG_HS_HCCHAR1", 0x520),
            new RegLabel("OTG_HS_HCCHAR2", 0x540),
            new RegLabel("OTG_HS_HCCHAR3", 0x560),
            new RegLabel("OTG_HS_HCCHAR4", 0x580),
            new RegLabel("OTG_HS_HCCHAR5", 0x5A0),
            new RegLabel("OTG_HS_HCCHAR6", 0x5c0),
            new RegLabel("OTG_HS_HCCHAR7", 0x5e0),
            new RegLabel("OTG_HS_HCCHAR8", 0x600),
            new RegLabel("OTG_HS_HCCHAR9", 0x620),
            new RegLabel("OTG_HS_HCCHAR10", 0x640),
            new RegLabel("OTG_HS_HCCHAR11", 0x660),

            new RegLabel("OTG_HS_DCFG", 0x800),
            new RegLabel("OTG_HS_DCTL", 0x804),
            new RegLabel("OTG_HS_DSTS", 0x808),
            new RegLabel("OTG_HS_DIEPMSK", 0x810),
            new RegLabel("OTG_HS_DOEPMSK", 0x814),
            new RegLabel("OTG_HS_DAINT", 0x818),
            new RegLabel("OTG_HS_DAINTMSK", 0x81C),
            new RegLabel("OTG_HS_DVBUSDIS", 0x828),
            new RegLabel("OTG_HS_DVBUSPULSE", 0x82C),
            new RegLabel("OTG_HS_DIEPEMPMSK", 0x834),
            new RegLabel("OTG_HS_DEACHINT", 0x838),
            new RegLabel("OTG_HS_DEACHINTMSK", 0x83C),
            new RegLabel("OTG_HS_DIEPEACHMSK1", 0x844),
            new RegLabel("OTG_HS_DOEPEACHMSK1", 0x884),

            new RegLabel("OTG_HS_DIEPCTL0", 0x900),
            new RegLabel("OTG_HS_DIEPCTL1", 0x920),
            new RegLabel("OTG_HS_DIEPCTL2", 0x940),
            new RegLabel("OTG_HS_DIEPCTL3", 0x960),
            new RegLabel("OTG_HS_DIEPCTL4", 0x980),
            new RegLabel("OTG_HS_DIEPCTL5", 0x9A0),
            new RegLabel("OTG_HS_DIEPCTL6", 0x9C0),
            new RegLabel("OTG_HS_DIEPCTL7", 0x9E0),
            
            new RegLabel("OTG_HS_DIEPCTL0", 0x900),
            new RegLabel("OTG_HS_DIEPINTx", 0x908),
            new RegLabel("OTG_HS_DIEPTSIZ0", 0x910),
            new RegLabel("OTG_HS_DIEPTSIZ1", 0x930),
            new RegLabel("OTG_HS_DIEPTSIZ1", 0x950),
            new RegLabel("OTG_HS_DIEPTSIZ1", 0x970),
            new RegLabel("OTG_HS_DOEPCTL0", 0xB00),
            new RegLabel("OTG_HS_DOEPCTL1", 0xB20),
            new RegLabel("OTG_HS_DOEPCTL2", 0xB40),
            new RegLabel("OTG_HS_DOEPCTL3", 0xB60),
            new RegLabel("OTG_HS_DOEPINT", 0xB08),
            new RegLabel("OTG_HS_DOEPTSIZ",0xB10),
	};
	

	private static class STM32InterruptVector{
		String name;
		int addr;
		private STM32InterruptVector(String name, int addr)
		{
			this.name = name;
			this.addr = addr;
		}
	}
	
	private static final STM32InterruptVector [] STM32IVT = {
			new STM32InterruptVector("RESET",0x4),
			new STM32InterruptVector("NMI",0x8),
			new STM32InterruptVector("HardFault",0xC),
			new STM32InterruptVector("MemManage",0x10),
			new STM32InterruptVector("BusFault",0x14),
			new STM32InterruptVector("UsageFault",0x18),
			new STM32InterruptVector("SVCall",0x2C),
			new STM32InterruptVector("Debug Monitor",0x30),
			new STM32InterruptVector("PendSV",0x38),
			new STM32InterruptVector("SysTick",0x3C),
			new STM32InterruptVector("WWDG",0x40),
			new STM32InterruptVector("PVD",0x44),
			new STM32InterruptVector("TAMP_STAMP",0x48),
			new STM32InterruptVector("RTC_WKUP",0x4C),
			new STM32InterruptVector("FLASH",0x50),
			new STM32InterruptVector("RCC",0x54),
			new STM32InterruptVector("EXTI0",0x58),
			new STM32InterruptVector("EXTI1",0x5C),
			new STM32InterruptVector("EXTI2",0x60),
			new STM32InterruptVector("EXTI3",0x64),
			new STM32InterruptVector("EXTI4",0x68),
			new STM32InterruptVector("DMA1_Stream0",0x6C),
			new STM32InterruptVector("DMA1_Stream1",0x70),
			new STM32InterruptVector("DMA1_Stream2",0x74),
			new STM32InterruptVector("DMA1_Stream3",0x78),
			new STM32InterruptVector("DMA1_Stream4",0x7C),
			new STM32InterruptVector("DMA1_Stream5",0x80),
			new STM32InterruptVector("DMA1_Stream6",0x84),
			new STM32InterruptVector("ADC",0x88),
			new STM32InterruptVector("CAN1_TX",0x8C),
			new STM32InterruptVector("CAN1_RX0",0x90),
			new STM32InterruptVector("CAN1_RX1",0x94),
			new STM32InterruptVector("CAN1_SCE",0x98),
			new STM32InterruptVector("EXTI9_5",0x9C),
			new STM32InterruptVector("TIM1_BRK_TIM9",0xA0),
			new STM32InterruptVector("TIM1_UP_TIM10",0xA4),
			new STM32InterruptVector("TIM1_TRG_COM_TIM11",0xA8),
			new STM32InterruptVector("TIM1_CC",0xAC),
			new STM32InterruptVector("TIM2",0xB0),
			new STM32InterruptVector("TIM3",0xB4),
			new STM32InterruptVector("TIM4",0xB8),
			new STM32InterruptVector("I2C1_EV",0xBc),
			new STM32InterruptVector("I2C1_ER",0xC0),
			new STM32InterruptVector("I2C2_EV",0xC4),
			new STM32InterruptVector("I2C2_ER",0xC8),
			new STM32InterruptVector("SPI1",0xCC),
			new STM32InterruptVector("SPI2",0xD0),
			new STM32InterruptVector("USART1",0xD4),
			new STM32InterruptVector("USART2",0xD8),
			new STM32InterruptVector("USART3",0xDC),
			new STM32InterruptVector("EXTI15_10",0xE0),
			new STM32InterruptVector("RTC_Alarm",0xE4),
			new STM32InterruptVector("OTG_FS_WKUP",0xE8),
			new STM32InterruptVector("TIM8_BRK_TIM12",0xEC),
			new STM32InterruptVector("TIM8_UP_TIM13",0xF0),
			new STM32InterruptVector("TIM8_TRG_COM_TIM14",0xF4),
			new STM32InterruptVector("TIM8_CC",0xF8),
			new STM32InterruptVector("DMA1_Stream7",0xFC),
			new STM32InterruptVector("FSMC",0x100),
			new STM32InterruptVector("SDIO",0x104),
			new STM32InterruptVector("TIM5",0x108),
			new STM32InterruptVector("SPI3",0x10C),
			new STM32InterruptVector("UART4",0x110),
			new STM32InterruptVector("UART5",0x114),
			new STM32InterruptVector("TIM6_DAC",0x118),
			new STM32InterruptVector("TIM7",0x11c),
			new STM32InterruptVector("DMA2_Stream0",0x120),
			new STM32InterruptVector("DMA2_Stream1",0x124),
			new STM32InterruptVector("DMA2_Stream2",0x128),
			new STM32InterruptVector("DMA2_Stream3",0x12C),
			new STM32InterruptVector("DMA2_Stream4",0x130),
			new STM32InterruptVector("ETH",0x134),
			new STM32InterruptVector("ETH_WKUP",0x138),
			new STM32InterruptVector("CAN2_TX",0x13C),
			new STM32InterruptVector("CAN2_RX0",0x140),
			new STM32InterruptVector("CAN2_RX1",0x144),
			new STM32InterruptVector("CAN2_SCE",0x148),
			new STM32InterruptVector("OTG_FS",0x14C),
			new STM32InterruptVector("DMA2_Stream5",0x150),
			new STM32InterruptVector("DMA2_Stream6",0x154),
			new STM32InterruptVector("DMA2_Stream7",0x158),
			new STM32InterruptVector("USART6",0x15C),
			new STM32InterruptVector("I2C3_EV",0x160),
			new STM32InterruptVector("I2C3_ER",0x164),
			new STM32InterruptVector("OTG_HS_EP1_OUT",0x168),
			new STM32InterruptVector("OTG_HS_EP1_IN",0x16C),
			new STM32InterruptVector("OTG_HS_WKUP",0x170),
			new STM32InterruptVector("OTG_HS",0x174),
			new STM32InterruptVector("DCMI",0x178),
			new STM32InterruptVector("CRYP",0x17C),
			new STM32InterruptVector("HACH_RNG",0x180),
		
		};	
	
	private static class STM32MemRegion {
		String name;
		int addr;
		int size;
		boolean read;
		boolean write;
		boolean execute;
		private STM32MemRegion(String name, int addr, int size, boolean read, boolean write, boolean execute) {
			this.name = name;
			this.addr = addr;
			this.size = size;
			this.read = read;
			this.write = write;
			this.execute = execute;
		}
	}
	// Pull these regions from the datasheet
	private static final STM32MemRegion [] STM32MEM = {
			new STM32MemRegion("TIM2",0x40000000,0x3FF,true,true,false),
			new STM32MemRegion("TIM3",0x40000400,0x3FF,true,true,false),
			new STM32MemRegion("TIM4",0x40000800,0x3FF,true,true,false),
			new STM32MemRegion("TIM5",0x40000C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM6",0x40001000,0x3FF,true,true,false),
			new STM32MemRegion("TIM7",0x40001400,0x3FF,true,true,false),
			new STM32MemRegion("TIM12",0x40001800,0x3FF,true,true,false),
			new STM32MemRegion("TIM13",0x40001C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM14",0x40002000,0x3FF,true,true,false),
			new STM32MemRegion("RTC/BKP",0x40002800,0x3FF,true,true,false),
			new STM32MemRegion("WWDG",0x40002C00,0x3FF,true,true,false),
			new STM32MemRegion("IWDG",0x40003000,0x3FF,true,true,false),
			new STM32MemRegion("SPI2/I2S2",0x40003800,0x3FF,true,true,false),
			new STM32MemRegion("SPI3/I2S3",0x40003C00,0x3FF,true,true,false),
			new STM32MemRegion("USART2",0x40004400,0x3FF,true,true,false),
			new STM32MemRegion("USART3",0x40004800,0x3FF,true,true,false),
			new STM32MemRegion("USART4",0x40004C00,0x3FF,true,true,false),
			new STM32MemRegion("USART5",0x40005000,0x3FF,true,true,false),
			new STM32MemRegion("I2C1",0x40005400,0x3FF,true,true,false),
			new STM32MemRegion("I2C2",0x40005800,0x3FF,true,true,false),
			new STM32MemRegion("I2C3",0x40005C00,0x3FF,true,true,false),
			new STM32MemRegion("CAN1",0x40006400,0x3FF,true,true,false),
			new STM32MemRegion("CAN2",0x40006800,0x3FF,true,true,false),
			new STM32MemRegion("PWR",0x40007000,0x3FF,true,true,false),
			new STM32MemRegion("DAC",0x40007400,0x3FF,true,true,false),
			new STM32MemRegion("TIM1",0x40010000,0x3FF,true,true,false),
			new STM32MemRegion("TIM8",0x40010400,0x3FF,true,true,false),
			new STM32MemRegion("USART1",0x40011000,0x3FF,true,true,false),
			new STM32MemRegion("USART6",0x40011400,0x3FF,true,true,false),
			new STM32MemRegion("ADC1/2/3",0x40012000,0x3FF,true,true,false),
			new STM32MemRegion("SDIO",0x40012C00,0x3FF,true,true,false),
			new STM32MemRegion("SPI1",0x40013000,0x3FF,true,true,false),
			new STM32MemRegion("SYSCFG",0x40013800,0x3FF,true,true,false),
			new STM32MemRegion("EXTI",0x40013C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM9",0x40014000,0x3FF,true,true,false),
			new STM32MemRegion("TIM10",0x40014400,0x3FF,true,true,false),
			new STM32MemRegion("TIM11",0x40014800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOA",0x40020000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOB",0x40020400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOC",0x40020800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOD",0x40020c00,0x3FF,true,true,false),
			new STM32MemRegion("GPIOE",0x40021000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOF",0x40021400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOG",0x40021800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOH",0x40021c00,0x3FF,true,true,false),
			new STM32MemRegion("GPIOI",0x40022000,0x3FF,true,true,false),
			new STM32MemRegion("CRC",0x40023000,0x3FF,true,true,false),
			new STM32MemRegion("RCC",0x40023800,0x3FF,true,true,false),
			new STM32MemRegion("Flash Interface Register",0x40023C00,0x3FF,true,true,false),
			new STM32MemRegion("BKPSRAM",0x40024000,0x3FF,true,true,false),
			new STM32MemRegion("DMA1",0x40026000,0x3FF,true,true,false),
			new STM32MemRegion("DMA2",0x40026400 ,0x3FF,true,true,false),
			new STM32MemRegion("Ethernet Mac",0x40028000 ,0x13FF,true,true,false),
			new STM32MemRegion("USB OTG HS",0x40040000 ,0x3FFFF,true,true,false),
			new STM32MemRegion("USB OTG FS",0x50000000 ,0x3FFFF,true,true,false),
			new STM32MemRegion("DCMI",0x50050000 ,0x3FF,true,true,false),
			new STM32MemRegion("CRYP",0x50060000 ,0x3FF,true,true,false),
			new STM32MemRegion("HASH",0x50060400 ,0x3FF,true,true,false),
			new STM32MemRegion("RNG",0x50060800 ,0x3FF,true,true,false),
			new STM32MemRegion("FSMC Control Register",0xA0000000 ,0xFFF,true,true,false),
			new STM32MemRegion("SRAM",0x20000000 ,0x20000,true,true,true),
			new STM32MemRegion("System Memory",0x1FFF0000 ,0x77FF,true,true,true),
			// TODO: Add the ability to select and load these in from the loader...
			new STM32MemRegion("OTP",0x1FFF7800 ,0x20F,true,false,false),
			new STM32MemRegion("Option Bytes",0x1FFFC000 ,0xF,true,false,false),
	};
	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "STM32F2";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		
		// The STM32 has a 32 bit Arm Cortex LE core, so that is the language that we will use
		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		FlatProgramAPI api = new FlatProgramAPI(program,monitor);
		InputStream inStream = provider.getInputStream(0);
		Memory mem = program.getMemory();
		// TODO: Load the bytes from 'provider' into the 'program'.
		// This is where we actually "Load" the program into ghidra
		
		// First we loop through our memory map that we created:
		for(STM32MemRegion memregion: STM32MEM)	{
			try {
				mem.createUninitializedBlock(memregion.name, api.toAddr(memregion.addr), memregion.size, false);
				api.createLabel(api.toAddr(memregion.addr),memregion.name.replace(" ","_"),false);
			} catch (LockException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (DuplicateNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (MemoryConflictException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (AddressOverflowException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			mem.createInitializedBlock("Main Memory", api.toAddr(0x8000000), inStream, 0xFFFFF, monitor, false);
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException
				| DuplicateNameException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			// Top of stack is first value in memory, see page 59 of datasheet
			// Make pointer, label it as stack start
			int stackAddr = mem.getInt(api.toAddr(0x8000000));
			Data stackAddrData = api.createDWord(api.toAddr(0x8000000));
			api.createLabel(api.toAddr(stackAddr),"_STACK_BEGIN",true);
			api.createMemoryReference(stackAddrData, api.toAddr(stackAddr), ghidra.program.model.symbol.RefType.DATA);
			
			// Mark the entry point of the binary, also referenced in the datasheet on page 59
			
			/*
			int entryPoint = mem.getInt(api.toAddr(0x8000004));
			Data entryPointData = api.createDWord(api.toAddr(0x8000004));
			api.createDWord(api.toAddr(0x8000004));
			api.createLabel(api.toAddr(entryPoint),"_ENTRY_POINT",true);
			api.createMemoryReference(entryPointData, api.toAddr(entryPoint), ghidra.program.model.symbol.RefType.DATA);
			*/
			for(STM32InterruptVector vector: STM32IVT) {
				int ptrVal = mem.getInt(api.toAddr(0x8000000+vector.addr));
				try {
				Data ptrData = api.createDWord(api.toAddr(0x8000000+vector.addr));
				api.createDWord(api.toAddr(0x8000000+vector.addr));
				api.createLabel(api.toAddr(0x8000000+vector.addr),vector.name,true);
				api.createMemoryReference(ptrData, api.toAddr(ptrVal), ghidra.program.model.symbol.RefType.DATA);
				} catch(ghidra.util.exception.InvalidInputException e) {
					// This is ugly, need to fix
					continue;
				}
			}
			
			for(RegLabel rlabel:USBHSRegs) {
				api.createLabel(api.toAddr(rlabel.addr+0x40040000),rlabel.label,true);
			}
			for(RegLabel rlabel:USBFSRegs) {
				api.createLabel(api.toAddr(rlabel.addr+0x50000000),rlabel.label,true);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
