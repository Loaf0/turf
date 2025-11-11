use std::io;
use std::mem;
use winapi::shared::minwindef::DWORD;
use winapi::um::winnt;
mod process;
use crate::process::Process;

fn test() {
    print_processes();

    println!("Enter a PID to open:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    let pid: u32 = input.trim().parse().expect("Please enter a valid number");

    let process = Process::open(pid).expect("Failed to open process");
    
    // filter memory regions based on permissions
    let mask = winnt::PAGE_EXECUTE_READWRITE | winnt::PAGE_EXECUTE_WRITECOPY | winnt::PAGE_READWRITE | winnt::PAGE_WRITECOPY;

    let regions = match process.memory_regions() {
        Ok(regions) => regions,
        Err(e) => {
            eprintln!("Failed to get memory regions: {}", e);
            return;
        }
    };

    let regions: Vec<_> = regions
        .into_iter()
        .filter(|p| (p.Protect & mask) != 0)
        .collect();

    eprintln!("Memory regions found : {}", regions.len());

    let target: i32 = 295;
    let target_bytes: [u8; 4] = target.to_ne_bytes();
    // list of eligable addresses
    let mut locations = Vec::with_capacity(regions.len());

    initial_scan(&process, &regions, &target_bytes, &mut locations);

    // this to adjust scans between calls or run until only one value remains
    // rescan the target to verify the target value stayed consistent
    let target: i32 = 295;
    let target_bytes: [u8; 4] = target.to_ne_bytes();
    rescan_locations(&process, &mut locations, &target_bytes);

}

pub fn enum_proc() -> io::Result<Vec<u32>> {
    let mut pids: Vec<u32> = Vec::with_capacity(1024);
    let mut size: u32 = 0;

    // collect all processes from winapi
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr(),
            // capacity is in bytes so must multiply by the size of DWORD to get proper size
            (pids.capacity() * mem::size_of::<DWORD>()) as u32,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let count = size as usize / mem::size_of::<DWORD>();
    unsafe {
        pids.set_len(count);
    }
    Ok(pids)
}

pub fn print_processes() {
    enum_proc()
        .unwrap()
        .into_iter()
        .for_each(|pid| match Process::open(pid) {
            Ok(proc) => match proc.name() {
                Ok(name) => println!("{}: {}", pid, name),
                Err(e) => println!("{}: (failed to get name: {})", pid, e),
            },
            _ => {}
        });
}

fn rescan_locations(process: &Process, locations: &mut Vec<usize>, target_bytes: &[u8]) {
    locations.retain(|addr| match process.read_memory(*addr, target_bytes.len()) {
        Ok(memory) => {
            if memory == target_bytes {
                true
            } else {
                println!("Value at address {:x} changed during rescan.", addr);
                false
            }
        }
        Err(_) => {
            println!("Failed to read address {:x} during rescan.", addr);
            false
        }
    });
}

fn initial_scan(
    process: &Process,
    regions: &[winapi::um::winnt::MEMORY_BASIC_INFORMATION],
    target_bytes: &[u8],
    locations: &mut Vec<usize>,
) {
    for region in regions {
        match process.read_memory(region.BaseAddress as _, region.RegionSize) {
            Ok(memory) => {
                memory
                    .windows(target_bytes.len())
                    .enumerate()
                    .for_each(|(offset, window)| {
                        if window == target_bytes {
                            locations.push(region.BaseAddress as usize + offset);
                            println!(
                                "Found exact value at [{:?}+{:x}]",
                                region.BaseAddress, offset
                            );
                        }
                    });
            }
            Err(err) => eprintln!(
                "Failed to read {} bytes at {:?}: {}",
                region.RegionSize, region.BaseAddress, err,
            ),
        }
    }
}

//     if regions.is_empty() {
//         eprintln!("No memory regions found.");
//     } else {
//         for region in &regions {
//             eprintln!(
//                 "Region:
//                 BaseAddress: {:?}
//                 AllocationBase: {:?}
//                 AllocationProtect: {:?}
//                 RegionSize: {:?}
//                 State: {:?}
//                 Protect: {:?}
//                 Type: {:?}",
//                 region.BaseAddress,
//                 region.AllocationBase,
//                 region.AllocationProtect,
//                 region.RegionSize,
//                 region.State,
//                 region.Protect,
//                 region.Type,
//             );
//         }
//     }