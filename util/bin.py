def bin_to_hex_array(file_path):
    hex_array = []
    with open(file_path, 'rb') as f:
        byte = f.read(1)
        while byte:
            hex_byte = "0x{:02x}".format(ord(byte))
            hex_array.append(hex_byte)
            byte = f.read(1)
    return hex_array

def bin_to_bytes_array(file_path):
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
        return data