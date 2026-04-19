import datetime
from hashlib import md5
from io import BytesIO
from os import makedirs, listdir, getcwd, sep
from os.path import isdir, isfile, join as osjoin, dirname, relpath, splitext
# from PIL import Image  # 原脚本引入但未使用，已注释保留
from struct import pack, unpack
from zlib import compress, decompress

# 第三方库（本地自定义模块，需确保 libraries 目录存在）
from libraries.pyvz2nineteendo import LogError, blue_print, green_print, initialize, path_input, list_levels
from libraries.pyvz2rijndael import RijndaelCBC
from libraries.pyvz2rton import JSONDecoder

# 全局配置字典（已清理键名末尾冗余空格）
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

# RSG 补丁相关函数
class SectionError(Exception):
    pass

def extend_to_4096(number):
    """按 4KB 对齐填充零字节"""
    return b"\0" * ((4096 - number) & 4095)

def rsg_patch_data(RSG_NAME, file, pathout_data, patch, patchout, level):
    """解析并打补丁至 RSG/PGSR 数据块"""
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

    data = None
    if level < 5:
        try:
            patch_data = open(osjoin(patch, RSG_NAME + ".section"), "rb").read()
            patch_length = len(patch_data)
            if patch_length == DECOMPRESSED_DATA_SIZE:
                data = patch_data
            else:
                raise SectionError(f"区块尺寸不匹配: 实际 {patch_length}, 预期 {DECOMPRESSED_DATA_SIZE}")
        except FileNotFoundError:
            pass
    elif COMPRESSION_FLAGS & 2 == 0:  # 未压缩文件
        data = bytearray(pathout_data[DATA_OFFSET: DATA_OFFSET + COMPRESSED_DATA_SIZE])
    elif COMPRESSED_DATA_SIZE != 0:  # 压缩文件
        data = bytearray(decompress(pathout_data[DATA_OFFSET: DATA_OFFSET + COMPRESSED_DATA_SIZE]))

    image_data = None
    if DECOMPRESSED_IMAGE_DATA_SIZE != 0:
        if level < 5:
            try:
                patch_data = open(osjoin(patch, RSG_NAME + ".section2"), "rb").read()
                if len(patch_data) == DECOMPRESSED_IMAGE_DATA_SIZE:
                    image_data = patch_data
                else:
                    raise SectionError(f"图像区块尺寸不匹配: 实际 {len(patch_data)}, 预期 {DECOMPRESSED_IMAGE_DATA_SIZE}")
            except FileNotFoundError:
                pass
        elif COMPRESSION_FLAGS & 1 == 0:  # 未压缩图像
            image_data = bytearray(pathout_data[IMAGE_DATA_OFFSET: IMAGE_DATA_OFFSET + COMPRESSED_IMAGE_DATA_SIZE])
        else:  # 压缩图像
            image_data = bytearray(decompress(pathout_data[IMAGE_DATA_OFFSET: IMAGE_DATA_OFFSET + COMPRESSED_IMAGE_DATA_SIZE]))

    if level > 4:
        DATA_DICT = {}
        IMAGE_DATA_DICT = {}
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
            IS_IMAGE = unpack("<I", file.read(4))[0] == 1
            FILE_OFFSET = unpack("<I", file.read(4))[0]
            FILE_SIZE = unpack("<I", file.read(4))[0]
            if IS_IMAGE:
                file.seek(20, 1)
                temp = file.tell()
                IMAGE_DATA_DICT[DECODED_NAME] = {"FILE_INFO": temp, "FILE_OFFSET": FILE_OFFSET}
            else:
                temp = file.tell()
                DATA_DICT[DECODED_NAME] = {"FILE_INFO": temp, "FILE_OFFSET": FILE_OFFSET}

        DECODED_NAME = ""
        DATA_SHIFT = 0
        for DECODED_NAME_NEW in sorted(DATA_DICT, key=lambda key: DATA_DICT[key]["FILE_OFFSET"]):
            FILE_OFFSET_NEW = DATA_SHIFT + DATA_DICT[DECODED_NAME_NEW]["FILE_OFFSET"]
            if DECODED_NAME:
                NAME_CHECK = DECODED_NAME.replace("\\", "/").lower()
                FILE_INFO = DATA_DICT[DECODED_NAME]["FILE_INFO"]
                if NAME_CHECK.startswith(pathStartsWith) and NAME_CHECK.endswith(pathEndsWith):
                    try:
                        if level < 7:
                            file_name = osjoin(patch, DECODED_NAME)
                            patch_data = open(file_name, "rb").read()
                        elif NAME_CHECK[-5:] == ".rton":
                            file_name = osjoin(patch, DECODED_NAME[:-5] + ".JSON")
                            patch_data = encode_root_object(open(file_name, "rb"))
                        else:
                            raise FileNotFoundError

                        if NAME_CHECK[-5:] == ".rton" and level > 5 and (overrideEncryption == 1 or (overrideEncryption < 0 and data[FILE_OFFSET: FILE_OFFSET + 2] == b"\x10\0")) and patch_data[:2] != b"\x10\0":
                            patch_data = b'\x10\0' + rijndael_cbc.encrypt(patch_data)

                        FILE_SIZE = len(patch_data)
                        patch_data += extend_to_4096(FILE_SIZE)
                        data[FILE_OFFSET: FILE_OFFSET_NEW] = patch_data
                        pathout_data[FILE_INFO - 4: FILE_INFO] = pack("<I", FILE_SIZE)
                        DATA_SHIFT += FILE_OFFSET + len(patch_data) - FILE_OFFSET_NEW
                        FILE_OFFSET_NEW = FILE_OFFSET + len(patch_data)
                        print(f"已修补: {relpath(file_name, patchout)}")
                    except FileNotFoundError:
                        pass
                    except Exception as e:
                        error_message(e, f" 修补 {file_name} 时发生错误")
                pathout_data[FILE_INFO - 8: FILE_INFO - 4] = pack("<I", FILE_OFFSET)
            FILE_OFFSET = FILE_OFFSET_NEW
            DECODED_NAME = DECODED_NAME_NEW

        DECODED_NAME = ""
        IMAGE_DATA_SHIFT = 0
        for DECODED_NAME_NEW in sorted(IMAGE_DATA_DICT, key=lambda key: IMAGE_DATA_DICT[key]["FILE_OFFSET"]):
            FILE_OFFSET_NEW = IMAGE_DATA_SHIFT + IMAGE_DATA_DICT[DECODED_NAME_NEW]["FILE_OFFSET"]
            if DECODED_NAME:
                NAME_CHECK = DECODED_NAME.replace("\\", "/").lower()
                FILE_INFO = IMAGE_DATA_DICT[DECODED_NAME]["FILE_INFO"]
                if NAME_CHECK.startswith(pathStartsWith) and NAME_CHECK.endswith(pathEndsWith):
                    try:
                        file_name = osjoin(patch, DECODED_NAME)
                        patch_data = open(file_name, "rb").read()
                        FILE_SIZE = len(patch_data)
                        if FILE_SIZE == 0:
                            warning_message(f"跳过空 PTX 文件: {file_name}")
                        else:
                            patch_data += extend_to_4096(FILE_SIZE)
                            image_data[FILE_OFFSET: FILE_OFFSET_NEW] = patch_data
                            pathout_data[FILE_INFO - 24: FILE_INFO - 20] = pack("<I", FILE_SIZE)
                            IMAGE_DATA_SHIFT += FILE_OFFSET + len(patch_data) - FILE_OFFSET_NEW
                            FILE_OFFSET_NEW = FILE_OFFSET + len(patch_data)
                            print(f"已修补: {relpath(file_name, patchout)}")
                    except FileNotFoundError:
                        pass
                    except Exception as e:
                        error_message(e, f" 修补 {file_name} 时发生错误")
                pathout_data[FILE_INFO - 28: FILE_INFO - 24] = pack("<I", FILE_OFFSET)
            FILE_OFFSET = FILE_OFFSET_NEW
            DECODED_NAME = DECODED_NAME_NEW

    if data is not None:
        if overrideDataCompression >= 0:
            COMPRESSION_FLAGS += overrideDataCompression - (COMPRESSION_FLAGS & 2)
        data += extend_to_4096(len(data))
        DECOMPRESSED_DATA_SIZE = len(data)
        if COMPRESSION_FLAGS & 2 == 0:
            COMPRESSED_DATA_SIZE = DECOMPRESSED_DATA_SIZE
        else:
            data = compress(data, 9)
            data += extend_to_4096(len(data))
            COMPRESSED_DATA_SIZE = len(data)
        pathout_data[DATA_OFFSET: IMAGE_DATA_OFFSET] = data
        pathout_data[28:36] = pack("<I", COMPRESSED_DATA_SIZE) + pack("<I", DECOMPRESSED_DATA_SIZE)
        pathout_data[40:44] = pack("<I", DATA_OFFSET + COMPRESSED_DATA_SIZE)
        if level < 5:
            print(f"已修补: {relpath(osjoin(patch, RSG_NAME + '.section'), patchout)}")

    if image_data is not None:
        if overrideImageDataCompression >= 0:
            COMPRESSION_FLAGS += overrideImageDataCompression - (COMPRESSION_FLAGS & 1)
        image_data += extend_to_4096(len(image_data))
        DECOMPRESSED_IMAGE_DATA_SIZE = len(image_data)
        if COMPRESSION_FLAGS & 1 == 0:
            COMPRESSED_IMAGE_DATA_SIZE = DECOMPRESSED_IMAGE_DATA_SIZE
        else:
            image_data = compress(image_data, 9)
            image_data += extend_to_4096(len(image_data))
            COMPRESSED_IMAGE_DATA_SIZE = len(image_data)
        pathout_data[IMAGE_DATA_OFFSET:] = image_data
        pathout_data[44:52] = pack("<I", COMPRESSED_IMAGE_DATA_SIZE) + pack("<I", DECOMPRESSED_IMAGE_DATA_SIZE)
        if level < 5:
            print(f"已修补: {relpath(osjoin(patch, RSG_NAME + '.section2'), patchout)}")

    pathout_data[16:20] = pack("<I", COMPRESSION_FLAGS)
    return pathout_data

def rsb_patch_data(file, pathout_data, patch, patchout, level):
    """解析并打补丁至 RSB/1BSR 数据块"""
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
    SUBGROUP_LIST = {}
    for i in range(SUBGROUP_INFO_ENTRIES):
        RSG_INFO = file.tell()
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
        SUBGROUP_LIST[RSG_NAME] = {
            "RSG_OFFSET": RSG_OFFSET,
            "RSG_SIZE": RSG_IMAGE_DATA_OFFSET + RSG_COMPRESSED_IMAGE_DATA_SIZE,
            "RSG_INFO": RSG_INFO
        }

    RSG_SHIFT = 0
    for RSG_NAME in sorted(SUBGROUP_LIST, key=lambda key: SUBGROUP_LIST[key]["RSG_OFFSET"]):
        RSG_OFFSET = RSG_SHIFT + SUBGROUP_LIST[RSG_NAME]["RSG_OFFSET"]
        RSG_SIZE = SUBGROUP_LIST[RSG_NAME]["RSG_SIZE"]
        info_start = SUBGROUP_LIST[RSG_NAME]["RSG_INFO"]
        RSG_CHECK = RSG_NAME.lower()
        if RSG_CHECK.startswith(rsgStartsWith) and RSG_CHECK.endswith(rsgEndsWith):
            try:
                if level < 4:
                    file_path = osjoin(patch, RSG_NAME + ".rsg")
                    subdata = bytearray(open(file_path, "rb").read())
                else:
                    subdata = pathout_data[RSG_OFFSET: RSG_OFFSET + RSG_SIZE]
                    subdata[16:36] = pathout_data[info_start + 140:info_start + 160]
                    subdata[40:52] = pathout_data[info_start + 164:info_start + 176]
                    subdata = rsg_patch_data(RSG_NAME, BytesIO(subdata), subdata, patch, patchout, level)

                subdata[:4] = b"pgsr"
                subdata += extend_to_4096(len(subdata))
                pathout_data[RSG_OFFSET: RSG_OFFSET + RSG_SIZE] = subdata
                pathout_data[info_start + 132:info_start + 136] = pack("<I", len(subdata))
                pathout_data[info_start + 140:info_start + 176] = subdata[16:36] + subdata[32:36] + subdata[40:52]
                RSG_SHIFT += len(subdata) - RSG_SIZE
                if level < 4:
                    print(f"已应用: {relpath(file_path, patchout)}")
            except FileNotFoundError:
                pass
            except Exception as e:
                error_message(e, f" 修补 {RSG_NAME}.rsg 时发生错误")
        pathout_data[info_start + 128:info_start + 132] = pack("<I", RSG_OFFSET)
    return pathout_data

def file_to_folder(inp, out, patch, level, extensions, pathout, patchout):
    """递归处理文件/目录转换与补丁应用"""
    if isfile(inp):
        try:
            file = open(inp, "rb")
            HEADER = file.read(4)
            COMPRESSED = HEADER == b"\xD4\xFE\xAD\xDE" and level > 2
            if COMPRESSED:
                DECOMPRESSED_SIZE = unpack("<I", file.read(4))[0]
                pathout_data = decompress(file.read())
                file = BytesIO(pathout_data)
                file.name = inp
                HEADER = file.read(4)

            if HEADER == b"1bsr":
                if not COMPRESSED:
                    pathout_data = HEADER + file.read()
                    file.seek(4)
                if level > 2:
                    pathout_data = rsb_patch_data(file, bytearray(pathout_data), patch, patchout, level)
                if level < 3 or COMPRESSED:
                    tag, extension = splitext(out)
                    tag += ".tag" + extension
                    open(tag, "wb").write(md5(pathout_data).hexdigest().upper().encode() + b"\r\n")
                    green_print(f"已写入: {relpath(tag, pathout)}")
                    pathout_data = b"\xD4\xFE\xAD\xDE" + pack("<I", len(pathout_data)) + compress(pathout_data, level=9)
                open(out, "wb").write(pathout_data)
                green_print(f"已写入: {relpath(out, pathout)}")
            elif HEADER == b"pgsr":
                try:
                    pathout_data = bytearray(HEADER + file.read())
                    file.seek(0)
                    pathout_data = rsg_patch_data("data", file, pathout_data, patch, patchout, level)
                    open(out, "wb").write(pathout_data)
                    green_print(f"已写入: {relpath(out, pathout)}")
                except Exception as e:
                    error_message(e, f" 修补 {inp} 时发生错误")
            elif level > 2:
                warning_message(f"未知的 1BSR 头 ({HEADER.hex()}) 位于 {inp}")
        except Exception as e:
            error_message(e, f" 在 {inp} 位置 {repr(file.tell())} 发生错误: Failed OBBPatch: ")
    elif isdir(inp):
        makedirs(out, exist_ok=True)
        makedirs(patch, exist_ok=True)
        for entry in sorted(listdir(inp)):
            input_file = osjoin(inp, entry)
            output_file = osjoin(out, entry)
            patch_file = osjoin(patch, entry)
            if isfile(input_file):
                if level < 3:
                    output_file += ".smf"
                if entry.lower().endswith(extensions):
                    file_to_folder(input_file, output_file, splitext(patch_file)[0], level, extensions, pathout, patchout)
            elif input_file != pathout and inp != patchout:
                file_to_folder(input_file, output_file, patch_file, level, extensions, pathout, patchout)

def conversion(inp, out, level, extensions, pathout):
    """单文件编码/解码转换"""
    if isfile(inp):
        try:
            file = open(inp, "rb")
            if file.read(4) == b"RTON":
                if level < 7:
                    open(out, "wb").write(b'\x10\0' + rijndael_cbc.encrypt(b"RTON" + file.read()))
                    print(f"已写入: {relpath(out, pathout)}")
            elif level > 6:
                file.seek(0)
                encoded_data = encode_root_object(file)
                open(out, "wb").write(encoded_data)
                print(f"已写入: {relpath(out, pathout)}")
        except Exception as e:
            error_message(e, f" 在 {inp} 发生错误")
    elif isdir(inp):
        makedirs(out, exist_ok=True)
        for entry in listdir(inp):
            input_file = osjoin(inp, entry)
            output_file = osjoin(out, entry)
            if isfile(input_file):
                check = entry.lower()
                if level > 6:
                    output_file = output_file[:-5]
                    if "" == splitext(output_file)[1] and not check.startswith(RTONNoExtensions):
                        output_file += ".rton"
                if check[-5:] == extensions:
                    conversion(input_file, output_file, level, extensions, pathout)
            elif input_file != pathout:
                conversion(input_file, output_file, level, extensions, pathout)

# ================= 主程序入口 =================
try:
    application_path = initialize()
    logerror = LogError(osjoin(application_path, "fail.txt"))
    error_message = logerror.error_message
    warning_message = logerror.warning_message
    input_level = logerror.input_level
    logerror.check_version(3, 9, 0)
    
    print("""\033[95m
\033[1mOBBPatcher v1.2.0 (c) 2022 Nineteendo\033[22m
\033[1m代码基础:\033[22m Luigi Auriemma, Small Pea & 1Zulu
\033[1m文档支持:\033[22m Watto Studios, YingFengTingYu, TwinKleS-C & h3x4n1um
\033[1m关注 PyVZ2 开发:\033[22m \033[4mhttps://discord.gg/CVZdcGKVSw\033[24m
\033[0m""")
    
    options = logerror.load_template(options, osjoin(application_path, "options"), 2)
    level_to_name = ["指定", "SMF", "RSB", "RSG", "SECTION", "ENCRYPTED", "ENCODED", "DECODED"]
    list_levels(level_to_name)
    
    options["encodedUnpackLevel"] = input_level("编码解包级别", 6, 7, options["encodedUnpackLevel"])
    options["encryptedUnpackLevel"] = input_level("加密解包级别", 5, 6, options["encryptedUnpackLevel"])
    options["rsgUnpackLevel"] = input_level("RSG/RSB/SMF 解包级别", 3, 7, options["rsgUnpackLevel"])
    options["rsbUnpackLevel"] = input_level("RSB/SMF 解包级别", 2, 3, options["rsbUnpackLevel"])
    options["smfUnpackLevel"] = input_level("SMF 解包级别", 1, 2, options["smfUnpackLevel"])
    
    if options["rsgStartsWithIgnore"]:
        rsgStartsWith = ""
    else:
        rsgStartsWith = options["rsgStartsWith"]
    if options["rsgEndsWithIgnore"]:
        rsgEndsWith = ""
    else:
        rsgEndsWith = options["rsgEndsWith"]

    # 修复原脚本中 str.encode() 的不规范写法，改为标准 .encode()
    rijndael_cbc = RijndaelCBC(options["encryptionKey"].encode(), 24)
    
    if 7 >= options["rsgUnpackLevel"] > 3:
        list_levels(["指定", "默认", "禁用", "启用"])
        overrideDataCompression = 2 * (input_level("数据压缩覆盖", 1, 3, options["overrideDataCompression"]) - 2)
        overrideImageDataCompression = input_level("图像数据压缩覆盖", 1, 3, options["overrideImageDataCompression"]) - 2
    if 7 >= options["rsgUnpackLevel"] > 5:
        overrideEncryption = input_level("加密覆盖", 1, 3, options["overrideEncryption"]) - 2

    if options["pathEndsWithIgnore"]:
        pathEndsWith = ""
    else:
        pathEndsWith = options["pathEndsWith"]
    if options["pathStartsWithIgnore"]:
        pathStartsWith = ""
    else:
        pathStartsWith = options["pathStartsWith"]
        
    RTONNoExtensions = options["RTONNoExtensions"]
    encode_root_object = JSONDecoder().encode_root_object

    blue_print(f"\n当前工作目录: {getcwd()}")
    
    if 7 >= options["encodedUnpackLevel"] > 6:
        encoded_input = path_input(f"编码 {level_to_name[options['encodedUnpackLevel']]} 输入文件/目录", options["encodedUnpacked"])
        if isfile(encoded_input):
            encoded_output = path_input("编码输出文件", options["encodedPacked"])
        else:
            encoded_output = path_input("编码输出目录", options["encodedPacked"])
    if 6 >= options["encryptedUnpackLevel"] > 5:
        encrypted_input = path_input(f"加密 {level_to_name[options['encryptedUnpackLevel']]} 输入文件/目录", options["encryptedUnpacked"])
        if isfile(encrypted_input):
            encrypted_output = path_input("加密输出文件", options["encryptedPacked"])
        else:
            encrypted_output = path_input("加密输出目录", options["encryptedPacked"])
    if 7 >= options["rsgUnpackLevel"] > 3:
        rsg_input = path_input("RSG/RSB/SMF 输入文件/目录", options["rsgPacked"])
        if isfile(rsg_input):
            rsg_output = path_input("RSG/RSB/SMF 修改后文件", options["rsgPatched"])
        else:
            rsg_output = path_input("RSG/RSB/SMF 修改后目录", options["rsgPatched"])
        rsg_patch = path_input(f"RSG/RSB/SMF {level_to_name[options['rsgUnpackLevel']]} 补丁目录", options["rsgUnpacked"])
    if 3 >= options["rsbUnpackLevel"] > 2:
        rsb_input = path_input("RSB/SMF 输入文件/目录", options["rsbPacked"])
        if isfile(rsb_input):
            rsb_output = path_input("RSB/SMF 修改后文件", options["rsbPatched"])
        else:
            rsb_output = path_input("RSB/SMF 修改后目录", options["rsbPatched"])
        rsb_patch = path_input(f"RSB/SMF {level_to_name[options['rsbUnpackLevel']]} 补丁目录", options["rsbUnpacked"])
    if 2 >= options["smfUnpackLevel"] > 1:
        smf_input = path_input(f"SMF {level_to_name[options['smfUnpackLevel']]} 输入文件/目录", options["smfUnpacked"])
        if isfile(smf_input):
            smf_output = path_input("SMF 输出文件", options["smfPacked"])
        else:
            smf_output = path_input("SMF 输出目录", options["smfPacked"])

    # 开始执行转换/补丁流程
    start_time = datetime.datetime.now()
    if 7 >= options["encodedUnpackLevel"] > 6:
        conversion(encoded_input, encoded_output, options["encodedUnpackLevel"], ".json", dirname(encoded_output))
    if 6 >= options["encryptedUnpackLevel"] > 5:
        conversion(encrypted_input, encrypted_output, options["encryptedUnpackLevel"], ".rton", dirname(encrypted_output))
    if 7 >= options["rsgUnpackLevel"] > 3:
        file_to_folder(rsg_input, rsg_output, rsg_patch, options["rsgUnpackLevel"], options["rsgExtensions"], dirname(rsg_output), rsg_patch)
    if 3 >= options["rsbUnpackLevel"] > 2:
        file_to_folder(rsb_input, rsb_output, rsb_patch, options["rsbUnpackLevel"], options["rsbExtensions"], dirname(rsb_output), rsb_patch)
    if 2 >= options["smfUnpackLevel"] > 1:
        file_to_folder(smf_input, smf_output, smf_output, options["smfUnpackLevel"], options["rsbExtensions"], dirname(smf_output), dirname(smf_output))

    logerror.finish_program("补丁处理完成，耗时: ", start_time)
except Exception as e:
    error_message(e)
except BaseException as e:
    warning_message(f"{type(e).__name__} : {e}")
finally:
    logerror.close()
