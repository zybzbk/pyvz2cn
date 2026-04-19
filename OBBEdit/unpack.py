import datetime
from io import BytesIO
from os import makedirs, listdir, getcwd, sep
from os.path import isdir, isfile, join as osjoin, dirname, relpath, splitext
# from PIL import Image  # 原脚本引入但未实际调用，已注释保留
from struct import unpack
from zlib import decompress

# 第三方库（本地自定义模块，需确保 libraries 目录存在）
from libraries.pyvz2nineteendo import LogError, blue_print, initialize, path_input, list_levels
from libraries.pyvz2rijndael import RijndaelCBC
from libraries.pyvz2rton import RTONDecoder

# 全局配置字典（已清理键名与字符串末尾冗余空格）
options = {
    # SMF 选项
    "smfExtensions": (".rsb.smf",),
    "smfPacked": "",
    "smfUnpacked": "",
    "smfUnpackLevel": 1,
    # RSB 选项
    "rsbExtensions": (".rsb.smf", ".1bsr", ".rsb1", ".rsb", ".obb"),
    "rsbPacked": "",
    "rsbPatched": "",
    "rsbUnpacked": "",
    "rsbUnpackLevel": 2,
    "rsgEndsWith": (),
    "rsgEndsWithIgnore": True,
    "rsgStartsWith": ("packages", "worldpackages_"),
    "rsgStartsWithIgnore": False,
    # RSG 选项
    "overrideDataCompression": 1,
    "overrideEncryption": 2,
    "overrideImageDataCompression": 1,
    "pathEndsWith": (".rton",),
    "pathEndsWithIgnore": False,
    "pathStartsWith": ("packages/",),
    "pathStartsWithIgnore": False,
    "rsgExtensions": (".rsb.smf", ".1bsr", ".rsb1", ".rsb", ".obb", ".pgsr", ".rsgp", ".rsg", ".rsg.smf"),
    "rsgPacked": "",
    "rsgPatched": "",
    "rsgUnpacked": "",
    "rsgUnpackLevel": 7,
    # 加密选项
    "encryptedExtensions": (".rton",),
    "encryptedPacked": "",
    "encryptedUnpacked": "",
    "encryptedUnpackLevel": 5,
    "encryptionKey": "00000000000000000000000000000000",
    # RTON 选项
    "comma": 0,
    "doublePoint": 1,
    "encodedPacked": "",
    "encodedUnpacked": "",
    "encodedUnpackLevel": 6,
    "ensureAscii": False,
    "indent": 4,
    "repairFiles": False,
    "RTONExtensions": (".bin", ".dat", ".json", ".rton", ".section"),
    "RTONNoExtensions": ("draper_", "local_profiles", "loot", "_saveheader_rton"),
    "sortKeys": False,
    "sortValues": False
}

# RSG 解包相关函数
def ARGB8888(file_data, WIDHT, HEIGHT):
    return Image.frombuffer("RGBA", (WIDHT, HEIGHT), file_data, "raw", "BGRA", 0, 1)

def ABGR8888(file_data, WIDHT, HEIGHT):
    return Image.frombuffer("RGBA", (WIDHT, HEIGHT), file_data, "raw", "RGBA", 0, 1)

def RGBA4444(file_data, WIDHT, HEIGHT):
    return Image.merge('RGBA', Image.frombuffer("RGBA", (WIDHT, HEIGHT), file_data, "raw", "RGBA;4B", 0, 1).split()[::-1])

def RGB565(file_data, WIDHT, HEIGHT):
    return Image.frombuffer("RGB", (WIDHT, HEIGHT), file_data, "raw", "BGR;16", 0, 1)

def RGBA5551(file_data, WIDHT, HEIGHT):
    img = Image.new('RGBA', (WIDHT, HEIGHT))
    index = 0
    for y in range(0, HEIGHT):
        for x in range(0, WIDHT):
            a = file_data[index]
            b = file_data[index + 1]
            img.putpixel((x, y), (b & 248, 36 * (b & 7) + (a & 192) // 8, 4 * (a & 62), 255 * (a & 1)))
            index += 2
    return img

def RGBABlock32x32(image_decoder, file_data, WIDHT, HEIGHT):
    BLOCK_OFFSET = 0
    img = Image.new('RGBA', (WIDHT, HEIGHT))
    for y in range(0, HEIGHT, 32):
        for x in range(0, WIDHT, 32):
            img.paste(image_decoder(file_data[BLOCK_OFFSET: BLOCK_OFFSET + 2048], 32, 32), (x, y))
            BLOCK_OFFSET += 2048
    return img

def RGBBlock32x32(image_decoder, file_data, WIDHT, HEIGHT):
    BLOCK_OFFSET = 0
    img = Image.new('RGB', (WIDHT, HEIGHT))
    for y in range(0, HEIGHT, 32):
        for x in range(0, WIDHT, 32):
            img.paste(image_decoder(file_data[BLOCK_OFFSET: BLOCK_OFFSET + 2048], 32, 32), (x, y))
            BLOCK_OFFSET += 2048
    return img

# 图像解码器映射表
rsb_image_decoders = {
    0: ARGB8888, 1: RGBA4444, 2: RGB565, 3: RGBA5551,
    21: RGBA4444, 22: RGB565, 23: RGBA5551
}
obb_image_decoders = {
    0: ABGR8888, 1: RGBA4444, 2: RGB565, 3: RGBA5551,
    21: RGBA4444, 22: RGB565, 23: RGBA5551
}

def rsg_extract(RSG_NAME, file, pathout_data, out, pathout, level):
    """解析并提取 RSG/PGSR 数据块"""
    try:
        HEADER = file.read(4)
        VERSION = unpack("<I", file.read(4))[0]
        file.seek(8, 1)
        COMPRESSION_FLAGS = unpack("<I", file.read(4))[0]
        HEADER_LENGTH = unpack("<I", file.read(4))[0]

        DATA_OFFSET = unpack("<I", file.read(4))[0]
        COMPRESSED_DATA_SIZE = unpack("<I", file.read(4))[0]
        DECOMPRESSED_DATA_SIZE = unpack("<I", file.read(4))[0]

        file.seek(4, 1)
        IMAGE_DATA_OFFSET = unpack("<I", file.read(4))[0]
        COMPRESSED_IMAGE_DATA_SIZE = unpack("<I", file.read(4))[0]
        DECOMPRESSED_IMAGE_DATA_SIZE = unpack("<I", file.read(4))[0]

        file.seek(20, 1)
        INFO_SIZE = unpack("<I", file.read(4))[0]
        INFO_OFFSET = unpack("<I", file.read(4))[0]
        INFO_LIMIT = INFO_OFFSET + INFO_SIZE

        # 提取主数据块
        if COMPRESSION_FLAGS & 2 == 0:
            data = bytearray(pathout_data[DATA_OFFSET: DATA_OFFSET + COMPRESSED_DATA_SIZE])
        elif COMPRESSED_DATA_SIZE != 0:
            data = bytearray(decompress(pathout_data[DATA_OFFSET: DATA_OFFSET + COMPRESSED_DATA_SIZE]))

        # 提取图像数据块
        image_data = None
        if DECOMPRESSED_IMAGE_DATA_SIZE != 0:
            if COMPRESSION_FLAGS & 1 == 0:
                image_data = bytearray(pathout_data[IMAGE_DATA_OFFSET: IMAGE_DATA_OFFSET + COMPRESSED_IMAGE_DATA_SIZE])
            else:
                image_data = bytearray(decompress(pathout_data[IMAGE_DATA_OFFSET: IMAGE_DATA_OFFSET + COMPRESSED_IMAGE_DATA_SIZE]))

        if level < 5:
            # 低级别解包：直接导出原始数据区块
            if COMPRESSION_FLAGS & 2 == 0 or COMPRESSED_DATA_SIZE != 0:
                file_path = osjoin(out, RSG_NAME + ".section")
                open(file_path, "wb").write(data)
                print(f"已写入: {relpath(file_path, pathout)}")
            if DECOMPRESSED_IMAGE_DATA_SIZE != 0:
                image_path = osjoin(out, RSG_NAME + ".section2")
                open(image_path, "wb").write(image_data)
                print(f"已写入: {relpath(image_path, pathout)}")
        else:
            # 高级别解包：解析内部文件结构
            NAME_DICT = {}
            temp = INFO_OFFSET
            file.seek(INFO_OFFSET)
            while temp < INFO_LIMIT:
                FILE_NAME = b""
                for key in list(NAME_DICT.keys()):
                    if NAME_DICT[key] + INFO_OFFSET < temp:
                        NAME_DICT.pop(key)
                    else:
                        FILE_NAME = key
                BYTE = b""
                while BYTE != b"\0":
                    FILE_NAME += BYTE
                    BYTE = file.read(1)
                    LENGTH = 4 * unpack("<I", file.read(3) + b"\0")[0]
                    if LENGTH != 0:
                        NAME_DICT[FILE_NAME] = LENGTH

                DECODED_NAME = FILE_NAME.decode().replace("\\", sep)
                NAME_CHECK = DECODED_NAME.replace("\\", "/").lower()
                IS_IMAGE = unpack("<I", file.read(4))[0] == 1
                FILE_OFFSET = unpack("<I", file.read(4))[0]
                FILE_SIZE = unpack("<I", file.read(4))[0]

                if IS_IMAGE:
                    file.seek(20, 1)

                if DECODED_NAME and NAME_CHECK.startswith(pathStartsWith) and NAME_CHECK.endswith(pathEndsWith):
                    if IS_IMAGE:
                        file_data_slice = image_data[FILE_OFFSET: FILE_OFFSET + FILE_SIZE]
                    else:
                        file_data_slice = data[FILE_OFFSET: FILE_OFFSET + FILE_SIZE]

                    # RTON 解密处理
                    if NAME_CHECK[-5:] == ".rton" and file_data_slice[:2] == b"\x10\0" and level > 5:
                        file_data_slice = rijndael_cbc.decrypt(file_data_slice[2:])

                    if NAME_CHECK[-5:] == ".rton" and level == 6 and file_data_slice[:4] != b"RTON":
                        warning_message(f"非标准 RTON 头: {file.name}: {DECODED_NAME}")
                    else:
                        file_path = osjoin(out, DECODED_NAME)
                        makedirs(dirname(file_path), exist_ok=True)
                        if level > 6:
                            if NAME_CHECK[-5:] == ".rton":
                                try:
                                    json_path = osjoin(out, DECODED_NAME[:-5] + ".JSON")
                                    source = BytesIO(file_data_slice)
                                    source.name = f"{file.name}: {DECODED_NAME}"
                                    source.read(4)  # 跳过 RTON 头
                                    encoded_data = parse_root_object(source)
                                    open(json_path, "wb").write(encoded_data)
                                    print(f"已写入: {relpath(json_path, pathout)}")
                                except Exception as e:
                                    error_message(e, f" 解析 {file.name}: {RSG_NAME}: {DECODED_NAME} 位置: {source.tell()}")
                            else:
                                open(file_path, "wb").write(file_data_slice)
                                print(f"已写入: {relpath(file_path, pathout)}")
                        else:
                            open(file_path, "wb").write(file_data_slice)
                            print(f"已写入: {relpath(file_path, pathout)}")
                temp = file.tell()
    except Exception as e:
        error_message(e, f" 提取 {file.name} 时发生错误")

def rsb_extract(file, pathout_data, out, level, pathout):
    """解析并提取 RSB/1BSR 数据块"""
    VERSION = unpack('<L', file.read(4))[0]
    file.seek(4, 1)
    HEADER_SIZE = unpack('<L', file.read(4))[0]
    FILE_LIST_SIZE = unpack('<L', file.read(4))[0]
    FILE_LIST_OFFSET = unpack('<L', file.read(4))[0]
    file.seek(8, 1)
    SUBGROUP_LIST_SIZE = unpack('<L', file.read(4))[0]
    SUBGROUP_LIST_OFFSET = unpack('<L', file.read(4))[0]
    SUBGROUP_INFO_ENTRIES = unpack("<I", file.read(4))[0]
    SUBGROUP_INFO_OFFSET = unpack("<I", file.read(4))[0]
    SUBGROUP_INFO_ENTRY_SIZE = unpack('<L', file.read(4))[0]
    GROUP_INFO_ENTRIES = unpack('<L', file.read(4))[0]
    GROUP_INFO_OFFSET = unpack('<L', file.read(4))[0]
    GROUP_INFO_ENTRY_SIZE = unpack('<L', file.read(4))[0]
    GROUP_LIST_SIZE = unpack('<L', file.read(4))[0]
    GROUP_LIST_OFFSET = unpack('<L', file.read(4))[0]
    AUTOPOOL_INFO_ENTRIES = unpack('<L', file.read(4))[0]
    AUTOPOOL_INFO_OFFSET = unpack('<L', file.read(4))[0]
    AUTOPOOL_INFO_ENTRY_SIZE = unpack('<L', file.read(4))[0]
    PTX_INFO_ENTRIES = unpack('<L', file.read(4))[0]
    PTX_INFO_OFFSET = unpack('<L', file.read(4))[0]
    PTX_INFO_ENTRY_SIZE = unpack('<L', file.read(4))[0]
    DIRECTORY_7_OFFSET = unpack('<L', file.read(4))[0]
    DIRECTORY_8_OFFSET = unpack('<L', file.read(4))[0]
    DIRECTORY_9_OFFSET = unpack('<L', file.read(4))[0]

    if VERSION == 4:
        HEADER_SIZE_2 = unpack('<L', file.read(4))[0]

    file.seek(SUBGROUP_INFO_OFFSET)
    for i in range(0, SUBGROUP_INFO_ENTRIES):
        info_start = file.tell()
        RSG_NAME = file.read(128).strip(b"\0").decode()
        RSG_OFFSET = unpack("<I", file.read(4))[0]
        RSG_SIZE = unpack("<I", file.read(4))[0]
        SUBGROUP_ID = unpack("<I", file.read(4))[0]
        RSG_COMPRESSION_FLAGS = unpack("<I", file.read(4))[0]
        RSG_HEADER_LENGTH = unpack("<I", file.read(4))[0]
        RSG_DATA_OFFSET = unpack("<I", file.read(4))[0]
        RSG_COMPRESSED_DATA_SIZE = unpack("<I", file.read(4))[0]
        RSG_DECOMPRESSED_DATA_SIZE = unpack("<I", file.read(4))[0]
        RSG_DECOMPRESSED_DATA_SIZE_B = unpack("<I", file.read(4))[0]
        RSG_IMAGE_DATA_OFFSET = unpack("<I", file.read(4))[0]
        RSG_COMPRESSED_IMAGE_DATA_SIZE = unpack("<I", file.read(4))[0]
        RSG_DECOMPRESSED_IMAGE_DATA_SIZE = unpack("<I", file.read(4))[0]
        file.seek(20, 1)
        IMAGE_ENTRIES = unpack("<I", file.read(4))[0]
        IMAGE_ID = unpack("<I", file.read(4))[0]

        RSG_CHECK = RSG_NAME.lower()
        RSG_SIZE = RSG_IMAGE_DATA_OFFSET + RSG_COMPRESSED_IMAGE_DATA_SIZE
        if RSG_CHECK.startswith(rsgStartsWith) and RSG_CHECK.endswith(rsgEndsWith):
            subdata = pathout_data[RSG_OFFSET: RSG_OFFSET + RSG_SIZE]
            subdata[:4] = b"pgsr"
            subdata[16:36] = pathout_data[info_start + 140:info_start + 160]
            subdata[40:52] = pathout_data[info_start + 164:info_start + 176]
            if level < 4:
                out_path = osjoin(out, RSG_NAME + ".rsg")
                open(out_path, "wb").write(subdata)
                print(f"已写入: {relpath(out_path, pathout)}")
            else:
                subfile = BytesIO(subdata)
                subfile.name = f"{file.name}: {RSG_NAME}"
                rsg_extract(RSG_NAME, subfile, subdata, out, pathout, level)

def file_to_folder(inp, out, level, extensions, pathout):
    """递归处理文件/目录转换与解包"""
    if isfile(inp):
        try:
            file = open(inp, "rb")
            HEADER = file.read(4)
            COMPRESSED = HEADER == b"\xD4\xFE\xAD\xDE"
            if COMPRESSED:
                DECOMPRESSED_SIZE = unpack("<I", file.read(4))[0]
                pathout_data = decompress(file.read())
                if level < 3:
                    open(out, "wb").write(pathout_data)
                    print(f"已写入: {relpath(out, pathout)}")
                else:
                    file = BytesIO(pathout_data)
                    file.name = inp
                    HEADER = file.read(4)
            if HEADER == b"1bsr":
                if not COMPRESSED:
                    pathout_data = HEADER + file.read()
                    file.seek(4)
                makedirs(out, exist_ok=True)
                rsb_extract(file, bytearray(pathout_data), out, level, pathout)
            elif HEADER == b"pgsr":
                pathout_data = HEADER + file.read()
                makedirs(out, exist_ok=True)
                file.seek(0)
                rsg_extract("data", file, pathout_data, out, pathout, level)
            elif level > 2:
                warning_message(f"未知的 1BSR 头 ({HEADER.hex()}) 位于 {inp}")
        except Exception as e:
            error_message(e, f" 在 {inp} 位置 {repr(file.tell())} 发生错误: Failed OBBUnpack: ")
    elif isdir(inp):
        makedirs(out, exist_ok=True)
        for entry in sorted(listdir(inp)):
            input_file = osjoin(inp, entry)
            output_file = osjoin(out, entry)
            if isfile(input_file):
                if entry.lower().endswith(extensions):
                    file_to_folder(input_file, splitext(output_file)[0], level, extensions, pathout)
            elif input_file != pathout:
                file_to_folder(input_file, output_file, level, extensions, pathout)

def conversion(inp, out, level, extensions, noextensions, pathout):
    """单文件加密/编码转换"""
    if isfile(inp):
        try:
            file = open(inp, "rb")
            HEADER = file.read(2)
            if HEADER == b"\x10\0":
                if level < 7:
                    open(out, "wb").write(rijndael_cbc.decrypt(file.read()))
                    print(f"已写入: {relpath(out, pathout)}")
            else:
                HEADER += file.read(2)
                if HEADER == b"RTON":
                    if level > 6:
                        data = parse_root_object(file)
                        open(out, "wb").write(data)
                        print(f"已写入: {relpath(out, pathout)}")
                elif inp.lower()[-5:] != ".json":
                    warning_message(f"未知的 RTON 头 ({HEADER.hex()}) 位于 {inp}")
        except Exception as e:
            error_message(e, f" 在 {inp} 位置 {repr(file.tell())} 发生错误")
    elif isdir(inp):
        makedirs(out, exist_ok=True)
        for entry in listdir(inp):
            input_file = osjoin(inp, entry)
            output_file = osjoin(out, entry)
            if isfile(input_file):
                check = entry.lower()
                if level > 6:
                    if check[-5:] == ".rton":
                        output_file = output_file[:-5]
                    output_file += ".json"
                if check.endswith(extensions) or check.startswith(noextensions):
                    conversion(input_file, output_file, level, extensions, noextensions, pathout)
            elif input_file != pathout:
                conversion(input_file, output_file, level, extensions, noextensions, pathout)

# ================= 主程序入口 =================
try:
    application_path = initialize()
    logerror = LogError(osjoin(application_path, "fail.txt"))
    error_message = logerror.error_message
    warning_message = logerror.warning_message
    input_level = logerror.input_level
    logerror.check_version(3, 9, 0)

    print("""\033[95m
\033[1mOBBUnpacker v1.2.0 (c) 2022 Nineteendo\033[22m
\033[1m代码基础:\033[22m Luigi Auriemma, Small Pea & 1Zulu
\033[1m文档支持:\033[22m Watto Studios, YingFengTingYu, TwinKleS-C & h3x4n1um
\033[1m关注 PyVZ2 开发:\033[22m \033[4mhttps://discord.gg/CVZdcGKVSw\033[24m
\033[0m""")

    options = logerror.load_template(options, osjoin(application_path, "options"), 1)
    level_to_name = ["指定", "SMF", "RSB", "RSG", "SECTION", "ENCRYPTED", "ENCODED", "DECODED"]
    list_levels(level_to_name)

    options["smfUnpackLevel"] = input_level("SMF 解包级别", 1, 2, options["smfUnpackLevel"])
    options["rsbUnpackLevel"] = input_level("RSB/SMF 解包级别", 2, 3, options["rsbUnpackLevel"])
    options["rsgUnpackLevel"] = input_level("RSG/RSB/SMF 解包级别", 3, 7, options["rsgUnpackLevel"])
    options["encryptedUnpackLevel"] = input_level("加密解包级别", 5, 6, options["encryptedUnpackLevel"])
    options["encodedUnpackLevel"] = input_level("编码解包级别", 6, 7, options["encodedUnpackLevel"])

    if options["rsgStartsWithIgnore"]:
        rsgStartsWith = ""
    else:
        rsgStartsWith = options["rsgStartsWith"]
    if options["rsgEndsWithIgnore"]:
        rsgEndsWith = ""
    else:
        rsgEndsWith = options["rsgEndsWith"]

    # 修复原脚本 str.encode() 的非标准写法
    rijndael_cbc = RijndaelCBC(options["encryptionKey"].encode(), 24)

    if options["pathEndsWithIgnore"]:
        pathEndsWith = ""
    else:
        pathEndsWith = options["pathEndsWith"]
    if options["pathStartsWithIgnore"]:
        pathStartsWith = ""
    else:
        pathStartsWith = options["pathStartsWith"]

    comma = b"," + b" " * options["comma"] if options["comma"] > 0 else b","
    doublePoint = b":" + b" " * options["doublePoint"] if options["doublePoint"] > 0 else b":"
    if options["indent"] is None:
        indent = current_indent = b" "
    elif options["indent"] < 0:
        current_indent = b"\r\n"
        indent = b"\t"
    else:
        current_indent = b"\r\n"
        indent = b"  " * options["indent"]

    ensureAscii = options["ensureAscii"]
    repairFiles = options["repairFiles"]
    sortKeys = options["sortKeys"]
    sortValues = options["sortValues"]
    parse_root_object = RTONDecoder(comma, current_indent, doublePoint, ensureAscii, indent, repairFiles, sortKeys, sortValues, warning_message).parse_root_object

    blue_print(f"\n当前工作目录: {getcwd()}")

    if 2 >= options["smfUnpackLevel"] > 1:
        smf_input = path_input("SMF 输入文件/目录", options["smfPacked"])
        smf_output = path_input(f"SMF {level_to_name[options['smfUnpackLevel']]} 输出文件/目录", options["smfUnpacked"])
    if 3 >= options["rsbUnpackLevel"] > 2:
        rsb_input = path_input("RSB/SMF 输入文件/目录", options["rsbPacked"])
        rsb_output = path_input(f"RSB/SMF {level_to_name[options['rsbUnpackLevel']]} 输出目录", options["rsbUnpacked"])
    if 7 >= options["rsgUnpackLevel"] > 3:
        rsg_input = path_input("RSG/RSB/SMF 输入文件/目录", options["rsgPacked"])
        rsg_output = path_input(f"RSG/RSB/SMF {level_to_name[options['rsgUnpackLevel']]} 输出目录", options["rsgUnpacked"])
    if 6 >= options["encryptedUnpackLevel"] > 5:
        encrypted_input = path_input("加密输入文件/目录", options["encryptedPacked"])
        encrypted_output = path_input(f"加密 {level_to_name[options['encryptedUnpackLevel']]} 输出文件/目录", options["encryptedUnpacked"])
    if 7 >= options["encodedUnpackLevel"] > 6:
        encoded_input = path_input("编码输入文件/目录", options["encodedPacked"])
        encoded_output = path_input(f"编码 {level_to_name[options['encodedUnpackLevel']]} 输出文件/目录", options["encodedUnpacked"])

    start_time = datetime.datetime.now()
    if 2 >= options["smfUnpackLevel"] > 1:
        file_to_folder(smf_input, smf_output, options["smfUnpackLevel"], options["smfExtensions"], dirname(smf_output))
    if 3 >= options["rsbUnpackLevel"] > 2:
        file_to_folder(rsb_input, rsb_output, options["rsbUnpackLevel"], options["rsbExtensions"], rsb_output)
    if 7 >= options["rsgUnpackLevel"] > 3:
        file_to_folder(rsg_input, rsg_output, options["rsgUnpackLevel"], options["rsgExtensions"], rsg_output)
    if 6 >= options["encryptedUnpackLevel"] > 5:
        conversion(encrypted_input, encrypted_output, options["encryptedUnpackLevel"], options["encryptedExtensions"], (), dirname(encrypted_output))
    if 7 >= options["encodedUnpackLevel"] > 6:
        conversion(encoded_input, encoded_output, options["encodedUnpackLevel"], options["RTONExtensions"], options["RTONNoExtensions"], dirname(encoded_output))

    logerror.finish_program("解包处理完成，耗时: ", start_time)
except Exception as e:
    error_message(e)
except BaseException as e:
    warning_message(f"{type(e).__name__} : {e}")
finally:
    logerror.close()
