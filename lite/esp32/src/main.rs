// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member on the Arduino Nano ESP32. So far it keeps its settings
//! in flash, joins the Wi-Fi network set on its console and runs a TLS 1.3
//! self-test on the protocol core; joining a group and syncing come next.

#![no_std]
#![no_main]

extern crate alloc;

#[cfg(all(feature = "board", feature = "qemu"))]
compile_error!("board and qemu are two different builds: pick one");
#[cfg(not(any(feature = "board", feature = "qemu")))]
compile_error!("pick a build: the feature board, or qemu for the QEMU test");

use cbb_core::error;
use esp_backtrace as _;
use esp_hal::flash::Flash;
#[cfg(feature = "board")]
use esp_hal::rng::{Trng, TrngSource};
use esp_println::println;

use crate::console::{Board, Console};
use crate::store::{Store, tag};

mod clock;
mod console;
#[cfg(feature = "board")]
mod net;
#[cfg(feature = "board")]
mod pair;
mod selftest;
mod store;

esp_bootloader_esp_idf::esp_app_desc!();

/// The source of getrandom, and so of every key and nonce of the core: the
/// chip's true random number generator, which needs an entropy source (the
/// ADC that main keeps running, and the radio). Without one it fails rather
/// than hand out numbers that are only pseudo-random.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom passes a buffer of len writable bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, len) };
    #[cfg(feature = "board")]
    Trng::try_new().map_err(|_| getrandom::Error::new_custom(1))?.read(buf);
    #[cfg(feature = "qemu")]
    qemu::fill(buf);
    Ok(())
}

/// The QEMU test build only: without esp-hal's init the chip's generator
/// does not work, so a fixed pseudo-random sequence stands in. Keys made
/// with it are not secret; this build only shows that the code runs.
#[cfg(feature = "qemu")]
mod qemu {
    use alloc::string::String;
    use core::sync::atomic::{AtomicU32, Ordering};

    static STATE: AtomicU32 = AtomicU32::new(0x9e37_79b9);

    pub fn fill(buf: &mut [u8]) {
        for b in buf {
            let mut x = STATE.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            STATE.store(x, Ordering::Relaxed);
            *b = x as u8;
        }
    }

    unsafe extern "C" {
        /// The ROM's UART reader: 0 and a byte, or nonzero when none waits.
        fn esp_rom_uart_rx_one_char(c: *mut u8) -> i32;
    }

    /// The QEMU build has no network.
    pub struct Board;

    impl crate::Board for Board {
        fn network(&self) -> String {
            "not in the QEMU build".into()
        }

        fn wifi(&mut self, _: Option<crate::store::Wifi>) {}

        fn join(&mut self, _: &str) -> cbb_core::error::Result<String> {
            Err(cbb_core::error::Error::msg("the QEMU build has no network to join a group over"))
        }
    }

    /// A byte from UART0, if one waits. esp-hal's UART driver needs the
    /// clocks that its init sets.
    pub fn read_byte() -> Option<u8> {
        let mut c = 0;
        // SAFETY: the ROM function writes one byte to c.
        (unsafe { esp_rom_uart_rx_one_char(&mut c) } == 0).then_some(c)
    }
}

/// Opens the settings and applies the saved debug mode.
fn open_store(flash: esp_hal::peripherals::FLASH<'static>) -> error::Result<Store> {
    let flash = Flash::new(flash, Default::default()).map_err(|e| error::Error::with("cannot open the flash", e))?;
    let store = Store::open(flash)?;
    if let Some(&[on]) = store.fields().get(tag::DEBUG) {
        error::set_show_details(on == 1);
    }
    Ok(store)
}

fn report(store: &error::Result<Store>) {
    if let Err(e) = store {
        println!("cbb-esp32: the settings are not available: {}", e.for_user());
    }
}

#[cfg(feature = "qemu")]
#[esp_hal::main]
fn main() -> ! {
    println!("cbb-esp32: QEMU test build, not for a real chip: its keys are not secret");
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 96 * 1024);
    // Espressif's QEMU does not emulate what esp-hal's init waits for (the
    // clocks' calibration); the ROM's set-up is enough for the flash.
    // SAFETY: nothing else takes the peripherals in this build.
    let peripherals = unsafe { esp_hal::peripherals::Peripherals::steal() };
    let mut store = open_store(peripherals.FLASH);
    report(&store);
    let mut board = qemu::Board;
    let mut console = Console::new();
    console.start();
    loop {
        match qemu::read_byte() {
            Some(b) => {
                console.feed(b, &mut store, &mut board);
            }
            None => core::hint::spin_loop(),
        }
    }
}

/// The Nano ESP32: Wi-Fi, and the phone that joins the board to a group.
#[cfg(feature = "board")]
struct Nano {
    spawner: embassy_executor::Spawner,
    stack: Option<embassy_net::Stack<'static>>,
}

#[cfg(feature = "board")]
impl Board for Nano {
    fn network(&self) -> alloc::string::String {
        net::status()
    }

    fn wifi(&mut self, wifi: Option<store::Wifi>) {
        net::want(wifi);
    }

    fn join(&mut self, name: &str) -> error::Result<alloc::string::String> {
        let stack = self.stack.ok_or_else(|| error::Error::msg("Wi-Fi did not start, so the board cannot join"))?;
        pair::start(self.spawner, stack, name)
    }
}

#[cfg(feature = "board")]
#[esp_hal::main]
async fn main(spawner: embassy_executor::Spawner) -> ! {
    use embassy_futures::select::{Either, select};
    use embedded_io_async::Read;
    use esp_hal::timer::timg::TimerGroup;
    use esp_hal::usb::usb_serial_jtag::UsbSerialJtag;

    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    // The ADC's noise makes the generator truly random while this lives.
    let _entropy = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 96 * 1024);
    esp_rtos::start(TimerGroup::new(peripherals.TIMG0).timer0);

    let mut store = open_store(peripherals.FLASH);
    report(&store);
    let wifi = store.as_ref().ok().and_then(Store::wifi);
    let stack = match net::start(spawner, peripherals.WIFI, wifi) {
        Ok(s) => Some(s),
        Err(e) => {
            println!("cbb-esp32: {}", e.for_user());
            None
        }
    };

    // The console reads the USB port; esp-println writes to it.
    let (mut rx, _tx) = UsbSerialJtag::new(peripherals.USB_DEVICE).into_async().split();
    let mut board = Nano { spawner, stack };
    let mut console = Console::new();
    console.start();
    let mut buf = [0u8; 64];
    loop {
        let n = match select(rx.read(&mut buf), pair::JOINED.wait()).await {
            Either::First(n) => n.unwrap_or(0),
            Either::Second(id) => {
                let saved = console::save_identity(&mut store, &id);
                if let Err(e) = &saved {
                    println!("cbb-esp32: {}", e.for_user());
                }
                pair::SAVED.signal(saved.is_ok());
                0
            }
        };
        for &b in &buf[..n] {
            console.feed(b, &mut store, &mut board);
        }
    }
}
