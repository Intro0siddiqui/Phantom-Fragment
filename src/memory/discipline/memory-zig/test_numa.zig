const std = @import("std");
const c = @cImport({
    @cInclude("stdio.h");
});

extern fn phantom_numa_available() c_int;
extern fn phantom_numa_max_node() c_int;

pub fn main() void {
    const available = phantom_numa_available();
    const max_node = phantom_numa_max_node();
    
    c.printf("NUMA Available: %d\n", available);
    c.printf("Max Node: %d\n", max_node);
}
