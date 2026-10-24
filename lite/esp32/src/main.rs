// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member on the Arduino Nano ESP32. This first step only proves
//! that the protocol core runs on the chip: a self-test makes two pairing
//! certificates and runs a TLS 1.3 handshake between them in memory.

#![no_std]
#![no_main]

extern crate alloc;

use esp_backtrace as _;
use esp_hal::main;
#[cfg(not(feature = "qemu"))]
use esp_hal::rng::{Trng, TrngSource};
use esp_println::println;

mod selftest;

esp_bootloader_esp_idf::esp_app_desc!();

/// The source of getrandom, and so of every key and nonce of the core: the
/// chip's true random number generator, which needs an entropy source (the
/// ADC that main keeps running, later also the radio). Without one it fails
/// rather than hand out numbers that are only pseudo-random.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom passes a buffer of len writable bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(dest, len) };
    #[cfg(not(feature = "qemu"))]
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
}

#[main]
fn main() -> ! {
    // Espressif's QEMU does not emulate what esp-hal's init waits for
    // (the clocks' calibration); the ROM's set-up is enough for the test.
    #[cfg(not(feature = "qemu"))]
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    // The ADC's noise makes the generator truly random while this lives.
    #[cfg(not(feature = "qemu"))]
    let _entropy = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 96 * 1024);

    #[cfg(feature = "qemu")]
    println!("cbb-esp32: QEMU test build, not for a real chip: its keys are not secret");
    println!("cbb-esp32: self-test");
    match selftest::run() {
        Ok(()) => println!("cbb-esp32: self-test passed"),
        Err(e) => println!("cbb-esp32: self-test failed: {e}"),
    }
    loop {
        core::hint::spin_loop();
    }
}
