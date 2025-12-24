from pwn import *
import os
import sys
import logging
import argparse

import colorlog
def get_logger(level=logging.INFO):
    # 创建logger对象
    logger = logging.getLogger()
    logger.setLevel(level)
    # 创建控制台日志处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    # 定义颜色输出格式
    color_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)s: %(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    # 将颜色输出格式添加到控制台日志处理器
    console_handler.setFormatter(color_formatter)
    # 移除默认的handler
    for handler in logger.handlers:
        logger.removeHandler(handler)
    # 将控制台日志处理器添加到logger对象
    logger.addHandler(console_handler)
    return logger

context.log_level = "error"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = get_logger()
logging.getLogger("pwnlib").setLevel(logging.ERROR)

class FuncDefinitionRetriever:
    target_file_path = None
    process = None
    libs = []

    def __init__(self, fs_path, filename, func_name):
        self.fs_path = os.path.abspath(fs_path)
        self.filename = os.path.basename(filename)
        self.func_name = func_name

    def find_target_file(self):
        for root, dirs, files in os.walk(self.fs_path):
            if self.filename in files:
                self.target_file_path = os.path.join(root, self.filename)

    def get_target_file_library(self):
        os.environ["QEMU_LD_PREFIX"] = self.fs_path
        elf = ELF(self.target_file_path, checksec=False)
        # check if target func is dynamic symbol
        if self.func_name in elf.sym:
            assert(self.func_name in elf.plt)
        self.p = elf.process()
        libs = self.p.libs()
        self.p.close()

        for key in libs:
            logger.debug(f"key: {key}")
            key_basename = os.path.basename(key)
            if "lib" in key_basename and ".so" in key_basename:
                self.libs.append(key)
                logger.info(f"get library: {key}")

    def find_func_symbol(self):
        for libc in self.libs:
            libc_file = ELF(libc, checksec=False)
            if self.func_name in libc_file.sym:
                if self.func_name not in libc_file.plt:
                    return libc
        return None

    def locate_function(self):
        self.find_target_file()
        if self.target_file_path == None:
            logger.warning(f"target file {self.filename} not found!")
            raise NameError
        else:
            logger.info(f"target file found at {self.target_file_path}")

        self.get_target_file_library()
        if len(self.libs) == 0:
            logger.info("target file contains no libs")
            raise NameError
        else:
            logger.info(f"target file's libs retrieve success!")

        return self.find_func_symbol()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Locate which shared library defines a target function"
    )

    parser.add_argument(
        "-f", "--filesystem",
        required=True,
        help="filesystem root path (e.g. squashfs-root)"
    )

    parser.add_argument(
        "-n", "--filename",
        required=True,
        help="target executable filename"
    )

    parser.add_argument(
        "-t", "--function",
        required=True,
        help="target function name"
    )

    return parser.parse_args()


def main():
    args = parse_args()


    retriever = FuncDefinitionRetriever(
        args.filesystem,
        args.filename,
        args.function
    )

    libc = retriever.locate_function()

    if libc != None:
        logger.info(f"found libc {libc}")
    else:
        logger.warning(f"function not found in any library")

if __name__ == "__main__":
    main()
