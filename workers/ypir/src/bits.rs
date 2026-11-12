use spiral_rs::aligned_memory::AlignedMemory64;

pub fn as_bytes(a_m: &AlignedMemory64) -> &[u8] {
    unsafe { std::slice::from_raw_parts(a_m.as_ptr() as *const u8, a_m.len() * 8) }
}

pub fn as_bytes_mut(a_m: &mut AlignedMemory64) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(a_m.as_ptr() as *mut u8, a_m.len() * 8) }
}

pub fn write_bits(data: &mut [u8], mut val: u64, bit_offs: usize, mut num_bits: usize) {
    let mut byte_index = bit_offs / 8;
    let mut bit_index = bit_offs % 8;

    while num_bits > 0 && byte_index < data.len() {
        // Calculate how many bits can be written in the current byte.
        let bits_to_write = std::cmp::min(8 - bit_index, num_bits);

        // Create a bitmask with 'bits_to_write' set to 1.
        let bitmask = (1 << bits_to_write) - 1;

        // Shift 'val' to align the bits to write and apply the bitmask.
        let bits = (val & bitmask) << bit_index;

        // Write the bits to the current byte in the buffer.
        data[byte_index] |= bits as u8;

        // Update the number of bits left to write and bit_index.
        num_bits -= bits_to_write;
        bit_index += bits_to_write;

        if bit_index == 8 {
            // If we've filled the current byte, move to the next byte and reset bit_index.
            byte_index += 1;
            bit_index = 0;
        }

        // Shift 'val' to prepare for the next iteration.
        val >>= bits_to_write;
    }
}
pub fn read_bits(data: &[u8], bit_offs: usize, num_bits: usize) -> u64 {
    if num_bits > 64 || num_bits == 0 {
        panic!("Invalid number of bits: {}", num_bits);
    }

    let byte_pos = bit_offs / 8;
    let mut bit_pos = bit_offs % 8;

    let mut result: u64 = 0;

    let mut remaining_bits = num_bits;

    for i in byte_pos..data.len() {
        let can_take = std::cmp::min(8 - bit_pos, remaining_bits);

        let value = if can_take < 8 {
            (data[i] >> bit_pos) & ((1 << can_take) - 1)
        } else {
            data[i] >> bit_pos
        };

        result |= (value as u64) << (num_bits - remaining_bits);

        remaining_bits -= can_take;
        if remaining_bits == 0 {
            break;
        }

        // If we did not use a whole byte and there are still remaining bits
        // take the lower bits from this byte and the higher bits from the next byte
        if bit_pos + can_take < 8 {
            let from_next_byte = data[i] & ((1 << (bit_pos + can_take)) - 1);
            result |= (from_next_byte as u64) << (num_bits - remaining_bits);
            remaining_bits -= bit_pos + can_take;
        }

        bit_pos = 0; // For subsequent bytes, we start from the first bit
    }

    result
}

pub fn u64s_to_contiguous_bytes(data: &[u64], inp_mod_bits: usize) -> Vec<u8> {
    let total_sz = ((data.len() * inp_mod_bits) as f64 / 8.0).ceil() as usize;
    let mut out = vec![0u8; total_sz];
    let mut bit_offs = 0;
    for i in 0..data.len() {
        write_bits(&mut out, data[i], bit_offs, inp_mod_bits);
        bit_offs += inp_mod_bits;
    }
    out
}

pub fn contiguous_bytes_to_u64s(data: &[u8], out_mod_bits: usize) -> Vec<u64> {
    let mut out = vec![0u64; (data.len() * 8) / out_mod_bits];
    let mut bit_offs = 0;
    for i in 0..out.len() {
        out[i] = read_bits(&data, bit_offs, out_mod_bits);
        bit_offs += out_mod_bits;
    }
    out
}
