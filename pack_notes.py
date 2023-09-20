import struct

# Define the format string
format_string = "I 7s f"
# "I" represents an unsigned integer,
#  "7s" represents a 7-byte string,
#  and "f" represents a float.

# Values to pack
value1 = 42
value2 = b"Example"
value3 = 3.14

# Pack the values into a binary string
packed_data = struct.pack(format_string, value1, value2, value3)
print("Packed Data:", packed_data)

# Unpack the data to verify
#  floating point in pi is observed
unpacked_data = struct.unpack(format_string, packed_data)

print("Unpacked Data:", unpacked_data)
