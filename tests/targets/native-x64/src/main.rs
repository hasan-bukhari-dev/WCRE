#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("wcre-native-x64-target requires Windows x64.");

use std::hint::{black_box, spin_loop};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const GLOBAL_SENTINEL_VALUE: u64 = 0x1122_3344_5566_7788;
const HEAP_SENTINEL_VALUE: u64 = 0x8877_6655_4433_2211;

const LEVEL_ONE_SENTINEL: u64 = 0xA1A1_A1A1_A1A1_A1A1;
const LEVEL_TWO_SENTINEL: u64 = 0xB2B2_B2B2_B2B2_B2B2;
const LEVEL_THREE_SENTINEL: u64 = 0xC3C3_C3C3_C3C3_C3C3;

static GLOBAL_SENTINEL: AtomicU64 = AtomicU64::new(GLOBAL_SENTINEL_VALUE);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);

#[inline(never)]
fn level_one(heap_sentinel: &u64) {
    let level_one_sentinel = LEVEL_ONE_SENTINEL;

    level_two(heap_sentinel, &level_one_sentinel);

    black_box(level_one_sentinel);
}

#[inline(never)]
fn level_two(heap_sentinel: &u64, level_one_sentinel: &u64) {
    let level_two_sentinel = LEVEL_TWO_SENTINEL;

    level_three(heap_sentinel, level_one_sentinel, &level_two_sentinel);

    black_box(level_two_sentinel);
}

#[inline(never)]
fn level_three(heap_sentinel: &u64, level_one_sentinel: &u64, level_two_sentinel: &u64) {
    let level_three_sentinel = LEVEL_THREE_SENTINEL;

    println!("WCRE Controlled Native x64 Target");
    println!();
    println!("PID:                    {}", std::process::id());
    println!("Architecture:           x86_64");
    println!();

    println!("Known values");
    println!("------------");
    println!("Global sentinel:        0x{GLOBAL_SENTINEL_VALUE:016X}");
    println!("Heap sentinel:          0x{HEAP_SENTINEL_VALUE:016X}");
    println!("Level-one sentinel:     0x{LEVEL_ONE_SENTINEL:016X}");
    println!("Level-two sentinel:     0x{LEVEL_TWO_SENTINEL:016X}");
    println!("Level-three sentinel:   0x{LEVEL_THREE_SENTINEL:016X}");
    println!();

    println!("Known addresses");
    println!("---------------");
    println!(
        "GLOBAL_SENTINEL:        0x{:016X}",
        &GLOBAL_SENTINEL as *const AtomicU64 as usize
    );
    println!(
        "COUNTER:                0x{:016X}",
        &COUNTER as *const AtomicU64 as usize
    );
    println!(
        "Heap sentinel:          0x{:016X}",
        heap_sentinel as *const u64 as usize
    );
    println!(
        "level_one():            0x{:016X}",
        level_one as *const () as usize
    );
    println!(
        "level_two():            0x{:016X}",
        level_two as *const () as usize
    );
    println!(
        "level_three():          0x{:016X}",
        level_three as *const () as usize
    );
    println!(
        "Level-one stack local:  0x{:016X}",
        level_one_sentinel as *const u64 as usize
    );
    println!(
        "Level-two stack local:  0x{:016X}",
        level_two_sentinel as *const u64 as usize
    );
    println!(
        "Level-three stack local:0x{:016X}",
        &level_three_sentinel as *const u64 as usize
    );

    println!();
    println!("Entering controlled capture loop.");
    println!("Press Ctrl+C or terminate the process when finished.");

    io::stdout().flush().expect("failed to flush stdout");

    while !STOP.load(Ordering::Relaxed) {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

        let global = GLOBAL_SENTINEL.load(Ordering::Relaxed);

        let heap = unsafe { std::ptr::read_volatile(heap_sentinel as *const u64) };

        let level_one = unsafe { std::ptr::read_volatile(level_one_sentinel as *const u64) };

        let level_two = unsafe { std::ptr::read_volatile(level_two_sentinel as *const u64) };

        let level_three = unsafe { std::ptr::read_volatile(&level_three_sentinel as *const u64) };

        black_box((counter, global, heap, level_one, level_two, level_three));

        for _ in 0..4096 {
            spin_loop();
        }
    }

    black_box(level_three_sentinel);
}

fn main() {
    let heap_sentinel = Box::new(HEAP_SENTINEL_VALUE);

    level_one(&heap_sentinel);

    black_box(heap_sentinel);
}
