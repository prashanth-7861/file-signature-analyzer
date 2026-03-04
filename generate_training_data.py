"""
Generate synthetic training data for the ML File Classifier.

Creates sample files with proper binary headers/signatures for each
supported file type. Each file type gets multiple variations to provide
diverse training data.
"""

import os
import struct
import random
import json
import zlib

# Base output directory
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data")

# Number of variations per file type
NUM_VARIATIONS = 20


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def random_bytes(n):
    return bytes(random.randint(0, 255) for _ in range(n))


def generate_jpeg(out_dir, count):
    """Generate JPEG files with proper SOI/EOI markers."""
    ensure_dir(out_dir)
    for i in range(count):
        # JPEG: SOI (FF D8), APP0/JFIF or APP1/Exif marker, random data, EOI (FF D9)
        data = b'\xFF\xD8'
        if i % 2 == 0:
            # JFIF header
            jfif_header = b'\xFF\xE0' + struct.pack('>H', 16) + b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
            data += jfif_header
        else:
            # Exif header
            exif_header = b'\xFF\xE1' + struct.pack('>H', 14) + b'Exif\x00\x00MM\x00\x2A\x00\x08'
            data += exif_header
        # Add some quantization table markers and random compressed data
        data += b'\xFF\xDB' + struct.pack('>H', 67) + bytes(range(65))
        # Huffman table
        data += b'\xFF\xC4' + struct.pack('>H', 30) + random_bytes(28)
        # Start of frame
        data += b'\xFF\xC0' + struct.pack('>H', 11) + b'\x08' + struct.pack('>HH', 100 + i * 10, 100 + i * 10) + b'\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01'
        # SOS + random data
        data += b'\xFF\xDA' + struct.pack('>H', 12) + b'\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00'
        data += random_bytes(random.randint(500, 2000))
        data += b'\xFF\xD9'
        with open(os.path.join(out_dir, f"sample_{i}.jpg"), 'wb') as f:
            f.write(data)


def generate_png(out_dir, count):
    """Generate PNG files with proper signature and IHDR chunk."""
    ensure_dir(out_dir)
    for i in range(count):
        data = b'\x89PNG\r\n\x1A\n'
        # IHDR chunk
        width = 50 + i * 5
        height = 50 + i * 5
        ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
        ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
        data += struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
        # sRGB chunk
        srgb_data = b'\x00'
        srgb_crc = zlib.crc32(b'sRGB' + srgb_data) & 0xFFFFFFFF
        data += struct.pack('>I', 1) + b'sRGB' + srgb_data + struct.pack('>I', srgb_crc)
        # IDAT chunk with some compressed data
        raw_row = b'\x00' + bytes([random.randint(0, 255) for _ in range(width * 3)])
        compressed = zlib.compress(raw_row)
        idat_crc = zlib.crc32(b'IDAT' + compressed) & 0xFFFFFFFF
        data += struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
        # IEND chunk
        iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
        data += struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
        with open(os.path.join(out_dir, f"sample_{i}.png"), 'wb') as f:
            f.write(data)


def generate_gif(out_dir, count):
    """Generate GIF files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        version = b'GIF89a' if i % 2 == 0 else b'GIF87a'
        width, height = 50 + i, 50 + i
        # Header + Logical Screen Descriptor
        data = version + struct.pack('<HH', width, height)
        data += b'\xF7\x00\x00'  # packed field, bg color, pixel aspect
        # Global Color Table (256 * 3 = 768 bytes)
        data += bytes([random.randint(0, 255) for _ in range(768)])
        # Image Descriptor
        data += b'\x2C' + struct.pack('<HHHH', 0, 0, width, height) + b'\x00'
        # LZW minimum code size + some sub-blocks
        data += b'\x08'
        block = random_bytes(random.randint(20, 100))
        data += bytes([len(block)]) + block
        data += b'\x00'  # block terminator
        data += b'\x3B'  # trailer
        with open(os.path.join(out_dir, f"sample_{i}.gif"), 'wb') as f:
            f.write(data)


def generate_bmp(out_dir, count):
    """Generate BMP files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        width = 20 + i * 2
        height = 20 + i * 2
        row_size = ((width * 3 + 3) // 4) * 4
        pixel_data_size = row_size * height
        file_size = 54 + pixel_data_size
        # BMP Header
        data = b'BM'
        data += struct.pack('<I', file_size)
        data += b'\x00\x00\x00\x00'
        data += struct.pack('<I', 54)
        # DIB Header (BITMAPINFOHEADER)
        data += struct.pack('<I', 40)
        data += struct.pack('<i', width)
        data += struct.pack('<i', height)
        data += struct.pack('<HH', 1, 24)  # planes, bpp
        data += struct.pack('<I', 0)  # compression
        data += struct.pack('<I', pixel_data_size)
        data += struct.pack('<ii', 2835, 2835)  # ppm
        data += struct.pack('<II', 0, 0)
        # Pixel data
        for _ in range(height):
            row = random_bytes(width * 3)
            padding = b'\x00' * (row_size - width * 3)
            data += row + padding
        with open(os.path.join(out_dir, f"sample_{i}.bmp"), 'wb') as f:
            f.write(data)


def generate_tiff(out_dir, count):
    """Generate TIFF files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        if i % 2 == 0:
            byte_order = b'II'  # little-endian
            pack_fmt = '<'
        else:
            byte_order = b'MM'  # big-endian
            pack_fmt = '>'
        data = byte_order + struct.pack(f'{pack_fmt}H', 42)
        data += struct.pack(f'{pack_fmt}I', 8)  # offset to first IFD
        # IFD with a few basic tags
        num_entries = 4
        data += struct.pack(f'{pack_fmt}H', num_entries)
        # ImageWidth tag
        data += struct.pack(f'{pack_fmt}HHI', 256, 3, 1) + struct.pack(f'{pack_fmt}I', 100 + i)
        # ImageLength tag
        data += struct.pack(f'{pack_fmt}HHI', 257, 3, 1) + struct.pack(f'{pack_fmt}I', 100 + i)
        # BitsPerSample tag
        data += struct.pack(f'{pack_fmt}HHI', 258, 3, 1) + struct.pack(f'{pack_fmt}I', 8)
        # Compression tag
        data += struct.pack(f'{pack_fmt}HHI', 259, 3, 1) + struct.pack(f'{pack_fmt}I', 1)
        # Next IFD offset (0 = no more)
        data += struct.pack(f'{pack_fmt}I', 0)
        data += random_bytes(random.randint(200, 1000))
        with open(os.path.join(out_dir, f"sample_{i}.tiff"), 'wb') as f:
            f.write(data)


def generate_webp(out_dir, count):
    """Generate WebP files with RIFF/WEBP header."""
    ensure_dir(out_dir)
    for i in range(count):
        payload = random_bytes(random.randint(100, 1000))
        chunk_type = b'VP8 ' if i % 3 == 0 else (b'VP8L' if i % 3 == 1 else b'VP8X')
        chunk_data = random_bytes(random.randint(50, 500))
        chunk = chunk_type + struct.pack('<I', len(chunk_data)) + chunk_data
        if len(chunk) % 2 != 0:
            chunk += b'\x00'
        file_size = 4 + len(chunk)
        data = b'RIFF' + struct.pack('<I', file_size) + b'WEBP' + chunk
        with open(os.path.join(out_dir, f"sample_{i}.webp"), 'wb') as f:
            f.write(data)


def generate_pdf(out_dir, count):
    """Generate PDF files with proper header and basic structure."""
    ensure_dir(out_dir)
    for i in range(count):
        version = random.choice([b'%PDF-1.4', b'%PDF-1.5', b'%PDF-1.6', b'%PDF-1.7', b'%PDF-2.0'])
        content = version + b'\n'
        content += b'% \xe2\xe3\xcf\xd3\n'  # binary comment
        content += b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
        content += b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
        content += b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n'
        xref_offset = len(content)
        content += b'xref\n0 4\n'
        content += b'0000000000 65535 f \n'
        content += b'0000000015 00000 n \n'
        content += b'0000000066 00000 n \n'
        content += b'0000000125 00000 n \n'
        content += b'trailer\n<< /Size 4 /Root 1 0 R >>\n'
        content += b'startxref\n'
        content += str(xref_offset).encode() + b'\n'
        content += b'%%EOF\n'
        # Add some variation in size
        if i > 10:
            content += b'% ' + random_bytes(random.randint(100, 500)) + b'\n'
        with open(os.path.join(out_dir, f"sample_{i}.pdf"), 'wb') as f:
            f.write(content)


def generate_zip(out_dir, count):
    """Generate ZIP archive files."""
    import zipfile
    import io
    ensure_dir(out_dir)
    for i in range(count):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            for j in range(random.randint(1, 5)):
                zf.writestr(f"file_{j}.txt", f"Sample content {i}_{j} " + "x" * random.randint(10, 200))
        with open(os.path.join(out_dir, f"sample_{i}.zip"), 'wb') as f:
            f.write(buf.getvalue())


def generate_docx(out_dir, count):
    """Generate DOCX (Office Open XML) files - ZIP-based with specific structure."""
    import zipfile
    import io
    ensure_dir(out_dir)
    for i in range(count):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                '</Types>')
            zf.writestr('_rels/.rels',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                '</Relationships>')
            zf.writestr('word/document.xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f'<w:body><w:p><w:r><w:t>Sample document {i}</w:t></w:r></w:p></w:body>'
                '</w:document>')
        with open(os.path.join(out_dir, f"sample_{i}.docx"), 'wb') as f:
            f.write(buf.getvalue())


def generate_xlsx(out_dir, count):
    """Generate XLSX (Excel) files - ZIP-based with specific structure."""
    import zipfile
    import io
    ensure_dir(out_dir)
    for i in range(count):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                '</Types>')
            zf.writestr('_rels/.rels',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                '</Relationships>')
            zf.writestr('xl/workbook.xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
                '</workbook>')
            zf.writestr('xl/worksheets/sheet1.xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Data {i}</t></is></c></row></sheetData>'
                '</worksheet>')
        with open(os.path.join(out_dir, f"sample_{i}.xlsx"), 'wb') as f:
            f.write(buf.getvalue())


def generate_pptx(out_dir, count):
    """Generate PPTX (PowerPoint) files - ZIP-based with specific structure."""
    import zipfile
    import io
    ensure_dir(out_dir)
    for i in range(count):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
                '</Types>')
            zf.writestr('_rels/.rels',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
                '</Relationships>')
            zf.writestr('ppt/presentation.xml',
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                f'<p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>'
                '</p:presentation>')
        with open(os.path.join(out_dir, f"sample_{i}.pptx"), 'wb') as f:
            f.write(buf.getvalue())


def generate_mp3(out_dir, count):
    """Generate MP3 files with proper headers."""
    ensure_dir(out_dir)
    for i in range(count):
        data = b''
        if i % 3 == 0:
            # ID3v2 header
            data += b'ID3'
            data += b'\x03\x00'  # version 2.3
            data += b'\x00'  # flags
            # Size (syncsafe integer)
            size = random.randint(100, 500)
            data += bytes([
                (size >> 21) & 0x7F,
                (size >> 14) & 0x7F,
                (size >> 7) & 0x7F,
                size & 0x7F
            ])
            data += random_bytes(size)
        # MPEG audio frame header (sync word 0xFFE0 + bits for MPEG1 Layer3)
        # 0xFF 0xFB = MPEG1, Layer3, 128kbps, 44100Hz
        for _ in range(random.randint(5, 20)):
            data += b'\xFF\xFB\x90\x00'
            data += random_bytes(random.randint(200, 417))
        with open(os.path.join(out_dir, f"sample_{i}.mp3"), 'wb') as f:
            f.write(data)


def generate_wav(out_dir, count):
    """Generate WAV files with proper RIFF/WAVE header."""
    ensure_dir(out_dir)
    for i in range(count):
        sample_rate = random.choice([8000, 16000, 22050, 44100, 48000])
        num_channels = random.choice([1, 2])
        bits_per_sample = random.choice([8, 16, 24])
        num_samples = random.randint(100, 2000)
        bytes_per_sample = bits_per_sample // 8
        data_size = num_samples * num_channels * bytes_per_sample
        byte_rate = sample_rate * num_channels * bytes_per_sample
        block_align = num_channels * bytes_per_sample

        data = b'RIFF'
        data += struct.pack('<I', 36 + data_size)
        data += b'WAVE'
        # fmt chunk
        data += b'fmt '
        data += struct.pack('<I', 16)  # chunk size
        data += struct.pack('<HHIIHH', 1, num_channels, sample_rate, byte_rate, block_align, bits_per_sample)
        # data chunk
        data += b'data'
        data += struct.pack('<I', data_size)
        data += random_bytes(data_size)
        with open(os.path.join(out_dir, f"sample_{i}.wav"), 'wb') as f:
            f.write(data)


def generate_mp4(out_dir, count):
    """Generate MP4/MOV files with proper ISO BMFF structure."""
    ensure_dir(out_dir)
    brands = [b'isom', b'mp41', b'mp42', b'M4A ', b'M4V ', b'avc1', b'mp71', b'MSNV']
    for i in range(count):
        brand = brands[i % len(brands)]
        # ftyp box
        ftyp_data = brand + struct.pack('>I', 0x200) + brand + b'isom' + b'iso2'
        ftyp_box = struct.pack('>I', 8 + len(ftyp_data)) + b'ftyp' + ftyp_data
        # moov box (minimal)
        mvhd_data = b'\x00' * 4 + random_bytes(104)  # version + flags + data
        mvhd_box = struct.pack('>I', 8 + len(mvhd_data)) + b'mvhd' + mvhd_data
        moov_box = struct.pack('>I', 8 + len(mvhd_box)) + b'moov' + mvhd_box
        # mdat box with random data
        mdat_payload = random_bytes(random.randint(200, 1000))
        mdat_box = struct.pack('>I', 8 + len(mdat_payload)) + b'mdat' + mdat_payload
        data = ftyp_box + moov_box + mdat_box
        with open(os.path.join(out_dir, f"sample_{i}.mp4"), 'wb') as f:
            f.write(data)


def generate_avi(out_dir, count):
    """Generate AVI files with RIFF/AVI header."""
    ensure_dir(out_dir)
    for i in range(count):
        # AVI is RIFF with 'AVI ' form type
        avi_content = random_bytes(random.randint(200, 1000))
        # hdrl list
        avih_data = struct.pack('<I', 56) + random_bytes(56)
        avih_chunk = b'avih' + struct.pack('<I', len(avih_data)) + avih_data
        hdrl_list = b'LIST' + struct.pack('<I', 4 + len(avih_chunk)) + b'hdrl' + avih_chunk
        # movi list
        data_chunk = b'00dc' + struct.pack('<I', len(avi_content)) + avi_content
        if len(data_chunk) % 2 != 0:
            data_chunk += b'\x00'
        movi_list = b'LIST' + struct.pack('<I', 4 + len(data_chunk)) + b'movi' + data_chunk
        body = hdrl_list + movi_list
        data = b'RIFF' + struct.pack('<I', 4 + len(body)) + b'AVI ' + body
        with open(os.path.join(out_dir, f"sample_{i}.avi"), 'wb') as f:
            f.write(data)


def generate_mkv(out_dir, count):
    """Generate MKV (Matroska) files with EBML header."""
    ensure_dir(out_dir)
    for i in range(count):
        # EBML header element ID: 1A 45 DF A3
        data = b'\x1A\x45\xDF\xA3'
        # Size (using EBML variable-length encoding, keep it simple)
        inner_data = b''
        # EBMLVersion: 4286 (element ID) + 01 (size) + 01 (value)
        inner_data += b'\x42\x86\x81\x01'
        # EBMLReadVersion
        inner_data += b'\x42\xF7\x81\x01'
        # EBMLMaxIDLength
        inner_data += b'\x42\xF2\x81\x04'
        # EBMLMaxSizeLength
        inner_data += b'\x42\xF3\x81\x08'
        # DocType = "matroska" or "webm"
        doc_type = b'matroska' if i % 2 == 0 else b'webm'
        inner_data += b'\x42\x82' + bytes([0x80 | len(doc_type)]) + doc_type
        # DocTypeVersion
        inner_data += b'\x42\x87\x81\x04'
        # DocTypeReadVersion
        inner_data += b'\x42\x85\x81\x02'

        size = len(inner_data)
        data += bytes([0x80 | size]) + inner_data
        # Segment element
        data += b'\x18\x53\x80\x67'
        segment_data = random_bytes(random.randint(200, 800))
        data += b'\x01\x00\x00\x00' + struct.pack('>I', len(segment_data)) + segment_data
        with open(os.path.join(out_dir, f"sample_{i}.mkv"), 'wb') as f:
            f.write(data)


def generate_epub(out_dir, count):
    """Generate EPUB files - ZIP with specific structure."""
    import zipfile
    import io
    ensure_dir(out_dir)
    for i in range(count):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            # mimetype must be first and uncompressed
            zf.writestr('mimetype', 'application/epub+zip', compress_type=zipfile.ZIP_STORED)
            zf.writestr('META-INF/container.xml',
                '<?xml version="1.0"?>'
                '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
                '<rootfiles><rootfile full-path="content.opf" media-type="application/oebps-package+xml"/>'
                '</rootfiles></container>')
            zf.writestr('content.opf',
                '<?xml version="1.0"?>'
                f'<package xmlns="http://www.idpf.org/2007/opf" version="3.0"><metadata>Sample {i}</metadata></package>')
        with open(os.path.join(out_dir, f"sample_{i}.epub"), 'wb') as f:
            f.write(buf.getvalue())


def generate_html(out_dir, count):
    """Generate HTML files."""
    ensure_dir(out_dir)
    templates = [
        '<!DOCTYPE html>\n<html><head><title>Page {i}</title></head><body><h1>Hello {i}</h1><p>{content}</p></body></html>',
        '<html>\n<head><meta charset="utf-8"><title>Test {i}</title></head>\n<body><div class="container"><p>{content}</p></div></body></html>',
        '<!DOCTYPE html>\n<html lang="en"><head><meta name="viewport" content="width=device-width"><title>Doc {i}</title><style>body{{font-family:sans-serif}}</style></head><body><main>{content}</main></body></html>',
        '<HTML>\n<HEAD><TITLE>Page {i}</TITLE></HEAD>\n<BODY><TABLE><TR><TD>{content}</TD></TR></TABLE></BODY></HTML>',
    ]
    for i in range(count):
        template = templates[i % len(templates)]
        content = ' '.join(random.choice(['Lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur',
                                           'adipiscing', 'elit', 'sed', 'do', 'eiusmod']) for _ in range(random.randint(20, 100)))
        html = template.format(i=i, content=content)
        if i % 5 == 0:
            html = '\xef\xbb\xbf' + html  # BOM
        with open(os.path.join(out_dir, f"sample_{i}.html"), 'w', encoding='utf-8') as f:
            f.write(html)


def generate_xml(out_dir, count):
    """Generate XML files."""
    ensure_dir(out_dir)
    for i in range(count):
        root_tags = ['data', 'config', 'settings', 'document', 'records', 'catalog', 'feed']
        root = random.choice(root_tags)
        xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<{root}>\n'
        for j in range(random.randint(3, 15)):
            tag = random.choice(['item', 'entry', 'record', 'element', 'node'])
            xml += f'  <{tag} id="{j}">'
            xml += f'Value {i}_{j} ' + 'x' * random.randint(5, 50)
            xml += f'</{tag}>\n'
        xml += f'</{root}>\n'
        with open(os.path.join(out_dir, f"sample_{i}.xml"), 'w', encoding='utf-8') as f:
            f.write(xml)


def generate_json(out_dir, count):
    """Generate JSON files."""
    ensure_dir(out_dir)
    for i in range(count):
        if i % 3 == 0:
            # Object
            data = {
                "name": f"sample_{i}",
                "id": i,
                "values": [random.random() for _ in range(random.randint(3, 20))],
                "nested": {"key": f"value_{i}", "count": random.randint(1, 100)},
                "active": random.choice([True, False])
            }
        elif i % 3 == 1:
            # Array
            data = [{"index": j, "value": f"item_{j}", "score": round(random.random(), 3)}
                    for j in range(random.randint(5, 30))]
        else:
            # Deeper nesting
            data = {
                "config": {
                    "database": {"host": "localhost", "port": 5432 + i},
                    "cache": {"enabled": True, "ttl": random.randint(60, 3600)},
                    "features": [f"feature_{j}" for j in range(random.randint(2, 8))]
                }
            }
        with open(os.path.join(out_dir, f"sample_{i}.json"), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)


def generate_txt(out_dir, count):
    """Generate text files with various content."""
    ensure_dir(out_dir)
    words = ['the', 'quick', 'brown', 'fox', 'jumps', 'over', 'lazy', 'dog',
             'hello', 'world', 'data', 'file', 'text', 'sample', 'test',
             'alpha', 'beta', 'gamma', 'delta', 'processing', 'analysis',
             'system', 'report', 'output', 'input', 'module', 'function']
    for i in range(count):
        lines = []
        for _ in range(random.randint(5, 50)):
            line = ' '.join(random.choice(words) for _ in range(random.randint(5, 20)))
            lines.append(line.capitalize() + random.choice(['.', '!', '?', '...']))
        text = '\n'.join(lines) + '\n'
        with open(os.path.join(out_dir, f"sample_{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(text)


def generate_python(out_dir, count):
    """Generate Python source files."""
    ensure_dir(out_dir)
    for i in range(count):
        code = f'#!/usr/bin/env python3\n"""Module {i} for testing."""\n\nimport os\nimport sys\n\n'
        for j in range(random.randint(2, 6)):
            code += f'def function_{j}(arg1, arg2=None):\n'
            code += f'    """Function {j} docstring."""\n'
            code += f'    result = arg1 + {j}\n'
            code += f'    if arg2 is not None:\n'
            code += f'        result += arg2\n'
            code += f'    return result\n\n'
        code += f'\nclass Sample{i}:\n'
        code += f'    def __init__(self):\n'
        code += f'        self.value = {i}\n\n'
        code += f'    def process(self):\n'
        code += f'        return self.value * 2\n\n'
        code += f'\nif __name__ == "__main__":\n'
        code += f'    obj = Sample{i}()\n'
        code += f'    print(obj.process())\n'
        with open(os.path.join(out_dir, f"sample_{i}.py"), 'w', encoding='utf-8') as f:
            f.write(code)


def generate_javascript(out_dir, count):
    """Generate JavaScript source files."""
    ensure_dir(out_dir)
    for i in range(count):
        code = f'// Module {i}\n"use strict";\n\n'
        for j in range(random.randint(2, 5)):
            code += f'function compute_{j}(a, b) {{\n'
            code += f'    const result = a + b + {j};\n'
            code += f'    return result;\n}}\n\n'
        code += f'class Handler{i} {{\n'
        code += f'    constructor(config) {{\n'
        code += f'        this.config = config;\n'
        code += f'        this.count = {i};\n'
        code += f'    }}\n\n'
        code += f'    process(data) {{\n'
        code += f'        return data.map(item => item * this.count);\n'
        code += f'    }}\n}}\n\n'
        code += f'module.exports = {{ Handler{i} }};\n'
        with open(os.path.join(out_dir, f"sample_{i}.js"), 'w', encoding='utf-8') as f:
            f.write(code)


def generate_exe(out_dir, count):
    """Generate PE (Windows EXE) files with proper MZ/PE header."""
    ensure_dir(out_dir)
    for i in range(count):
        # MZ header
        data = b'MZ'
        data += struct.pack('<H', 0x90)  # bytes on last page
        data += struct.pack('<H', 3)  # pages
        data += struct.pack('<H', 0)  # relocations
        data += struct.pack('<H', 4)  # header size in paragraphs
        data += struct.pack('<H', 0)  # min extra paragraphs
        data += struct.pack('<H', 0xFFFF)  # max extra paragraphs
        data += struct.pack('<H', 0)  # initial SS
        data += struct.pack('<H', 0xB8)  # initial SP
        data += struct.pack('<H', 0)  # checksum
        data += struct.pack('<H', 0)  # initial IP
        data += struct.pack('<H', 0)  # initial CS
        data += struct.pack('<H', 0x40)  # relocation table offset
        data += struct.pack('<H', 0)  # overlay number
        data += b'\x00' * 8  # reserved
        data += struct.pack('<H', 0)  # OEM id
        data += struct.pack('<H', 0)  # OEM info
        data += b'\x00' * 20  # reserved
        data += struct.pack('<I', 0x80)  # PE header offset
        # DOS stub
        data += b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'
        data += b'This program cannot be run in DOS mode.\r\r\n$'
        data += b'\x00' * (0x80 - len(data))
        # PE signature
        data += b'PE\x00\x00'
        # COFF header
        data += struct.pack('<H', 0x14C)  # machine (i386)
        data += struct.pack('<H', 1)  # number of sections
        data += struct.pack('<I', 0x5F000000 + i)  # timestamp
        data += struct.pack('<I', 0)  # symbol table
        data += struct.pack('<I', 0)  # num symbols
        data += struct.pack('<H', 0xE0)  # optional header size
        data += struct.pack('<H', 0x102)  # characteristics
        # Optional header (PE32)
        data += struct.pack('<H', 0x10B)  # magic (PE32)
        data += random_bytes(0xDE)  # rest of optional header
        # Section header (.text)
        data += b'.text\x00\x00\x00'
        data += struct.pack('<I', 0x1000)  # virtual size
        data += struct.pack('<I', 0x1000)  # virtual address
        data += struct.pack('<I', 0x200)  # raw data size
        data += struct.pack('<I', 0x200)  # raw data pointer
        data += b'\x00' * 12  # relocs, line numbers
        data += struct.pack('<I', 0x60000020)  # characteristics
        # Some code-like data
        data += random_bytes(random.randint(200, 800))
        with open(os.path.join(out_dir, f"sample_{i}.exe"), 'wb') as f:
            f.write(data)


def generate_elf(out_dir, count):
    """Generate ELF executable files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        # ELF magic
        data = b'\x7FELF'
        # EI_CLASS: 1=32bit, 2=64bit
        elf_class = random.choice([1, 2])
        data += bytes([elf_class])
        # EI_DATA: 1=LE, 2=BE
        data += bytes([1])
        # EI_VERSION
        data += b'\x01'
        # EI_OSABI: 0=SYSV, 3=Linux
        data += bytes([random.choice([0, 3])])
        # EI_ABIVERSION + padding
        data += b'\x00' * 8
        if elf_class == 1:
            # 32-bit ELF header
            data += struct.pack('<H', 2)  # e_type: ET_EXEC
            data += struct.pack('<H', 3)  # e_machine: EM_386
            data += struct.pack('<I', 1)  # e_version
            data += struct.pack('<I', 0x8048000)  # e_entry
            data += struct.pack('<I', 52)  # e_phoff
            data += struct.pack('<I', 0)  # e_shoff
            data += struct.pack('<I', 0)  # e_flags
            data += struct.pack('<H', 52)  # e_ehsize
            data += struct.pack('<H', 32)  # e_phentsize
            data += struct.pack('<H', 1)  # e_phnum
            data += struct.pack('<H', 40)  # e_shentsize
            data += struct.pack('<H', 0)  # e_shnum
            data += struct.pack('<H', 0)  # e_shstrndx
        else:
            # 64-bit ELF header
            data += struct.pack('<H', 2)  # e_type
            data += struct.pack('<H', 0x3E)  # e_machine: EM_X86_64
            data += struct.pack('<I', 1)  # e_version
            data += struct.pack('<Q', 0x400000)  # e_entry
            data += struct.pack('<Q', 64)  # e_phoff
            data += struct.pack('<Q', 0)  # e_shoff
            data += struct.pack('<I', 0)  # e_flags
            data += struct.pack('<H', 64)  # e_ehsize
            data += struct.pack('<H', 56)  # e_phentsize
            data += struct.pack('<H', 1)  # e_phnum
            data += struct.pack('<H', 64)  # e_shentsize
            data += struct.pack('<H', 0)  # e_shnum
            data += struct.pack('<H', 0)  # e_shstrndx
        data += random_bytes(random.randint(200, 800))
        with open(os.path.join(out_dir, f"sample_{i}.elf"), 'wb') as f:
            f.write(data)


def generate_rar(out_dir, count):
    """Generate RAR archive files with proper signature."""
    ensure_dir(out_dir)
    for i in range(count):
        if i % 2 == 0:
            # RAR5 signature
            data = b'Rar!\x1A\x07\x01\x00'
        else:
            # RAR4 signature
            data = b'Rar!\x1A\x07\x00'
        # Archive header block
        data += b'\xCF\x90\x73\x00\x00\x0D\x00\x00\x00\x00\x00\x00\x00'
        data += random_bytes(random.randint(100, 500))
        with open(os.path.join(out_dir, f"sample_{i}.rar"), 'wb') as f:
            f.write(data)


def generate_7z(out_dir, count):
    """Generate 7-Zip archive files with proper signature."""
    ensure_dir(out_dir)
    for i in range(count):
        # 7z signature: 37 7A BC AF 27 1C
        data = b'\x37\x7A\xBC\xAF\x27\x1C'
        # Version
        data += struct.pack('<BB', 0, 4)  # major, minor version
        # Start header CRC
        data += struct.pack('<I', 0)
        # Next header offset
        data += struct.pack('<Q', 0)
        # Next header size
        data += struct.pack('<Q', 0)
        # Next header CRC
        data += struct.pack('<I', 0)
        data += random_bytes(random.randint(100, 500))
        with open(os.path.join(out_dir, f"sample_{i}.7z"), 'wb') as f:
            f.write(data)


def generate_flac(out_dir, count):
    """Generate FLAC audio files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        # fLaC magic
        data = b'fLaC'
        # STREAMINFO metadata block (mandatory, first)
        # Block type: 0 (STREAMINFO), last-block bit varies
        is_last = 0x80 if i % 2 == 0 else 0x00
        block_type = is_last | 0x00
        block_size = 34  # STREAMINFO is always 34 bytes
        data += bytes([block_type])
        data += struct.pack('>I', block_size)[1:]  # 3-byte big-endian size
        # STREAMINFO data
        data += struct.pack('>HH', 4096, 4096)  # min/max block size
        data += b'\x00\x00\x00' + b'\x00\x00\x00'  # min/max frame size (3 bytes each)
        sample_rate = 44100
        channels = 2
        bps = 16
        total_samples = random.randint(10000, 100000)
        # Pack: sample_rate(20), channels-1(3), bps-1(5), total_samples(36)
        packed = (sample_rate << 44) | ((channels - 1) << 41) | ((bps - 1) << 36) | total_samples
        data += struct.pack('>Q', packed)
        # MD5 signature (16 bytes)
        data += random_bytes(16)
        if not is_last:
            # Add a VORBIS_COMMENT block
            vc_data = struct.pack('<I', 7) + b'testing' + struct.pack('<I', 0)
            data += bytes([0x84])  # last block, type 4
            data += struct.pack('>I', len(vc_data))[1:]
            data += vc_data
        data += random_bytes(random.randint(200, 800))
        with open(os.path.join(out_dir, f"sample_{i}.flac"), 'wb') as f:
            f.write(data)


def generate_ogg(out_dir, count):
    """Generate OGG audio files with proper page header."""
    ensure_dir(out_dir)
    for i in range(count):
        # OGG page header
        data = b'OggS'  # capture pattern
        data += b'\x00'  # version
        data += b'\x02'  # header type (beginning of stream)
        data += struct.pack('<Q', 0)  # granule position
        data += struct.pack('<I', i + 1)  # serial number
        data += struct.pack('<I', 0)  # page sequence number
        data += struct.pack('<I', 0)  # CRC (placeholder)
        # Vorbis identification header
        vorbis_header = b'\x01vorbis'
        vorbis_header += struct.pack('<I', 0)  # version
        vorbis_header += bytes([2])  # channels
        vorbis_header += struct.pack('<I', 44100)  # sample rate
        vorbis_header += struct.pack('<i', 0)  # max bitrate
        vorbis_header += struct.pack('<i', 128000)  # nominal bitrate
        vorbis_header += struct.pack('<i', 0)  # min bitrate
        vorbis_header += bytes([0xB8])  # blocksize
        vorbis_header += b'\x01'  # framing
        num_segments = 1
        segment_size = len(vorbis_header)
        data += bytes([num_segments])
        data += bytes([segment_size])
        data += vorbis_header
        # Second page with more data
        data += b'OggS\x00\x00'
        data += struct.pack('<Q', 0)
        data += struct.pack('<I', i + 1)
        data += struct.pack('<I', 1)
        data += struct.pack('<I', 0)
        payload = random_bytes(random.randint(100, 400))
        data += bytes([1]) + bytes([len(payload) if len(payload) < 255 else 255])
        data += payload
        with open(os.path.join(out_dir, f"sample_{i}.ogg"), 'wb') as f:
            f.write(data)


def generate_svg(out_dir, count):
    """Generate SVG image files."""
    ensure_dir(out_dir)
    for i in range(count):
        colors = ['red', 'blue', 'green', 'purple', 'orange', '#336699', '#FF5500']
        shapes = []
        for j in range(random.randint(2, 8)):
            shape_type = random.choice(['circle', 'rect', 'line', 'ellipse'])
            color = random.choice(colors)
            if shape_type == 'circle':
                shapes.append(f'<circle cx="{random.randint(10, 190)}" cy="{random.randint(10, 190)}" r="{random.randint(5, 50)}" fill="{color}"/>')
            elif shape_type == 'rect':
                shapes.append(f'<rect x="{random.randint(0, 100)}" y="{random.randint(0, 100)}" width="{random.randint(10, 80)}" height="{random.randint(10, 80)}" fill="{color}"/>')
            elif shape_type == 'line':
                shapes.append(f'<line x1="{random.randint(0, 200)}" y1="{random.randint(0, 200)}" x2="{random.randint(0, 200)}" y2="{random.randint(0, 200)}" stroke="{color}" stroke-width="2"/>')
            else:
                shapes.append(f'<ellipse cx="{random.randint(10, 190)}" cy="{random.randint(10, 190)}" rx="{random.randint(10, 50)}" ry="{random.randint(10, 50)}" fill="{color}"/>')

        svg = f'<?xml version="1.0" encoding="UTF-8"?>\n'
        svg += f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">\n'
        svg += '  ' + '\n  '.join(shapes) + '\n'
        svg += f'  <text x="10" y="190" font-size="12">Sample {i}</text>\n'
        svg += '</svg>\n'
        with open(os.path.join(out_dir, f"sample_{i}.svg"), 'w', encoding='utf-8') as f:
            f.write(svg)


def generate_sqlite(out_dir, count):
    """Generate SQLite database files with proper header."""
    ensure_dir(out_dir)
    for i in range(count):
        # SQLite header (first 100 bytes)
        data = b'SQLite format 3\x00'  # 16 bytes magic
        page_size = random.choice([512, 1024, 2048, 4096])
        data += struct.pack('>H', page_size)
        data += b'\x01\x01'  # file format write/read version
        data += b'\x00'  # reserved space
        data += b'\x40\x20\x20'  # max/min embedded payload, leaf payload
        data += struct.pack('>I', 1)  # file change counter
        data += struct.pack('>I', random.randint(1, 10))  # database size in pages
        data += struct.pack('>I', 0)  # first freelist trunk page
        data += struct.pack('>I', 0)  # total freelist pages
        data += struct.pack('>I', random.randint(1, 100))  # schema cookie
        data += struct.pack('>I', 4)  # schema format number
        data += struct.pack('>I', 0)  # default page cache size
        data += struct.pack('>I', 0)  # largest root b-tree page
        data += struct.pack('>I', 1)  # text encoding (1=UTF-8)
        data += struct.pack('>I', 0)  # user version
        data += struct.pack('>I', 0)  # incremental vacuum mode
        data += struct.pack('>I', 0)  # application ID
        data += b'\x00' * 20  # reserved
        data += struct.pack('>I', random.randint(1, 100))  # version-valid-for
        data += struct.pack('>I', 3039000)  # SQLite version number
        # Pad to page size
        data += b'\x00' * (page_size - len(data))
        # Add some more pages
        for _ in range(random.randint(1, 5)):
            data += random_bytes(page_size)
        with open(os.path.join(out_dir, f"sample_{i}.sqlite"), 'wb') as f:
            f.write(data)


def main():
    """Generate all training data."""
    print("Generating ML training data...")
    print(f"Output directory: {OUTPUT_DIR}")
    random.seed(42)  # Reproducible

    generators = [
        ("JPEG Image", generate_jpeg),
        ("PNG Image", generate_png),
        ("GIF Image", generate_gif),
        ("BMP Image", generate_bmp),
        ("TIFF Image", generate_tiff),
        ("WebP Image", generate_webp),
        ("PDF Document", generate_pdf),
        ("ZIP Archive", generate_zip),
        ("Microsoft Word Document", generate_docx),
        ("Microsoft Excel Spreadsheet", generate_xlsx),
        ("Microsoft PowerPoint Presentation", generate_pptx),
        ("MP3 Audio", generate_mp3),
        ("WAV Audio", generate_wav),
        ("MP4 Video", generate_mp4),
        ("AVI Video", generate_avi),
        ("MKV Video", generate_mkv),
        ("EPUB eBook", generate_epub),
        ("HTML Document", generate_html),
        ("XML Document", generate_xml),
        ("JSON Data", generate_json),
        ("Text File", generate_txt),
        ("Python Source", generate_python),
        ("JavaScript Source", generate_javascript),
        ("EXE Executable", generate_exe),
        ("ELF Executable", generate_elf),
        ("RAR Archive", generate_rar),
        ("7-Zip Archive", generate_7z),
        ("FLAC Audio", generate_flac),
        ("OGG Audio", generate_ogg),
        ("SVG Image", generate_svg),
        ("SQLite Database", generate_sqlite),
    ]

    total_files = 0
    for label, generator in generators:
        out_dir = os.path.join(OUTPUT_DIR, label)
        print(f"  Generating {NUM_VARIATIONS} samples for: {label}")
        generator(out_dir, NUM_VARIATIONS)
        total_files += NUM_VARIATIONS

    print(f"\nDone! Generated {total_files} files across {len(generators)} file types.")
    print(f"Training data location: {OUTPUT_DIR}")
    return OUTPUT_DIR


if __name__ == "__main__":
    main()
