import datetime
from io import StringIO
from json import load
from os import listdir, system
from os.path import dirname, isfile, join as osjoin, realpath, splitext
import sys
from traceback import format_exc

def initialize():
    system(" ")
    if getattr(sys, "frozen", False):
        return dirname(sys.executable)
    else:
        return sys.path[0]

class LogError:
    def __init__(self, fail):
        try:
            self.fail = open(fail, "w")
        except PermissionError as e:
            self.fail = StringIO()
            self.fail.name = None
            self.error_message(e)

    def error_message(self, e, sub=" ", string=" "):
        # 打印并记录错误
        string += type(e).__name__ + sub + ": " + str(e) + "\n" + format_exc()
        self.fail.write(string + "\n")
        self.fail.flush()
        print("\033[91m" + string + "\033[0m")

    def warning_message(self, string):
        # 打印并记录警告
        self.fail.write("\t" + string + "\n")
        self.fail.flush()
        print("\33[93m" + string + "\33[0m")

    def check_version(self, mayor=2, minor=0, micro=0):
        if sys.version_info[:3] < (mayor, minor, micro):
            raise BaseException("必须使用 Python " + repr(mayor) + "." + repr(minor) + "." + repr(micro) + " 或更高版本")

    def input_level(self, text, minimum, maximum, preset):
        # 设置转换的输入等级
        try:
            if preset < minimum:
                return max(minimum, min(maximum, int(bold_input(text + " (" + str(minimum) + "-" + str(maximum) + ") "))))
            elif preset > minimum:
                print("\033[1m" + text + "\033[0m: " + repr(preset))
            return preset
        except Exception as e:
            self.error_message(e)
            self.warning_message("默认使用 " + str(minimum))
            return minimum

    def load_template(self, options, folder, index):
        # 将模板加载到选项中
        try:
            templates = {}
            blue_print("\033[1m模板:\033[0m ")
            for entry in sorted(listdir(folder)):
                if isfile(osjoin(folder, entry)):
                    file, extension = splitext(entry)
                    if extension == ".json" and entry.count("--") == 2:
                        dash_list = file.split("--")
                        key = dash_list[0].lower()
                        if key not in templates:
                            blue_print("\033[1m " + key + "\033[0m: " + dash_list[index])
                            templates[key] = entry
                    elif entry.count("--") > 0:
                        print("\033[1m " + "--".join(file.split("--")[1:]) + "\033[0m ")
            length = len(templates)
            if length == 0:
                green_print("已加载默认模板")
            else:
                if length > 1:
                    key = bold_input("选择模板").lower()
                
                name = templates[key]
                newoptions = load(open(osjoin(folder, name), "rb"))
                for key in options:
                    if key in newoptions and newoptions[key] != options[key]:
                        if type(options[key]) == type(newoptions[key]):
                            options[key] = newoptions[key]
                        elif isinstance(options[key], tuple) and isinstance(newoptions[key], list):
                            options[key] = tuple([str(i).lower() for i in newoptions[key]])
                        elif key == "indent" and newoptions[key] == None:
                            options[key] = newoptions[key]
                green_print("已加载模板 " + name)
        except Exception as e:
            self.error_message(e, "加载选项时：")
            self.warning_message("回退至默认选项。")
        return options

    def finish_program(self, message, start):
        green_print(message + "  " + str(datetime.datetime.now() - start))
        if self.fail.tell() > 0:
            name = self.fail.name
            if name == None:
                open(path_input("\33[93m发生错误，转储至\33[0m ", " "), "w").write(self.fail.getvalue())
            else:
                print("\33[93m发生错误，请查看：" + self.fail.name + "\33[0m ")
        bold_input("\033[95m按 [回车键] 继续")

    def close(self):
        # 关闭日志文件
        self.fail.close()

def blue_print(text):
    # 以蓝色打印文本
    print("\033[94m" + text + "\033[0m")

def green_print(text):
    # 以绿色打印文本
    print("\033[32m" + text + "\033[0m")

def bold_input(text):
    # 以粗体显示输入提示
    return input("\033[1m" + text + "\033[0m: ")

def path_input(text, preset):
    # 输入混合路径
    if preset != " ":
        print("\033[1m " + text + "\033[0m: " + preset)
        return preset
    else:
        string = " "
        newstring = bold_input(text)
        while newstring or string == " ":
            string = " "
            quoted = 0
            escaped = False
            temp_string = " "
            confirm = False
            for char in newstring:
                if escaped:
                    if quoted != 1 and char == "'" or quoted != 2 and char == '"' or quoted == 0 and char in "\\ ":
                        string += temp_string + char
                        confirm = True
                    else:
                        string += temp_string + "\\" + char
                    temp_string = " "
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif quoted != 2 and char == "'":
                    quoted = 1 - quoted
                elif quoted != 1 and char == '"':
                    quoted = 2 - quoted
                elif quoted != 0 or char != " ":
                    string += temp_string + char
                    temp_string = " "
                else:
                    temp_string += " "
            if string == " ":
                newstring = bold_input("\033[91m请输入路径")
            else:
                newstring = " "
                processed_string = realpath(string)
                if confirm or processed_string != string:
                    newstring = bold_input("确认 \033[100m " + processed_string)
        return processed_string

def list_levels(levels):
    blue_print("\n" + " ".join([repr(i) + "-" + levels[i] for i in range(len(levels))]))
