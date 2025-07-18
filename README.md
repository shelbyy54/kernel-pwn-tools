# kernel-pwn-tools
一个自用的，适用于ctf比赛的内核pwn头文件仓库
# 前言
本项目是由`arttnba3`在ctf-wiki上 https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/introduction/ 大佬的三个脚本所二次开发而来，主要用于ctf比赛的内核pwn

配套教程：https://www.cnblogs.com/resea/p/18971999

# 文件构成
本项目仅包含2个文件，均可单独使用
```
.
|- kernelpwn.h 包含常用的内核pwn函数
|- remort.py   用于编码传输exp的脚本
```
# `kernelpwn.h`使用方法

1. 复制或拉取`kernelpwn.h`到本地
2. 在`.c`文件开头
```C
#inclued "kernelpwn.h"
```
3.`gcc -masm=intel -no-pie -static -O2 -Wall -o A 1.c`

# `remort.py`使用方法 
1. 复制或拉取`remort.py`到本地
2. `chmod +x ./remort.py`
3. `remort.py -ip="127.0.0.1:1145" -exp="./exp" `
