#!/usr/bin/env python
#-*- coding:utf-8 -*-

import base64   #输出用base64编码
from tkinter import messagebox

FK=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]

CK=[0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279]

S=[[0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05],
[0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99],
[0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62],
[0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6],
[0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8],
[0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35],
[0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87],
[0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e],
[0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1],
[0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3],
[0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f],
[0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51],
[0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8],
[0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0],
[0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84],
[0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]]

# 将字符转换成八位的二进制 接收 l：字符串 返回值为字符串
def Str2bit(l):
    l=list(l)
    bit_list=[]
    for i in l:
        if 0<len(bin(ord(i)))<=10:
            bit_0b=bin(ord(i)).replace('0b','')
            bit_8=(8-len(bit_0b))*'0'+bit_0b
            bit_list.append(bit_8)
        else:
            messagebox.showerror('错误','输入有误')
            raise SystemError("输入有误")
    bit_list=''.join(bit_list)
    return bit_list

# 将明文/密文分成128bit一组 并填充 接收 s：字符串/字节 返回值为字符串列表
def Divide_128(s):
    stri=Str2bit(s)
    Plaintext_128=[]
    i=1
    while i <= len(stri)//128:
        Plaintext_128.append(stri[128*(i-1):128*i])
        i=i+1
    m=(128-(len(stri[128*(len(stri)//128):])))%128
    if m!=0 :
        Plaintext_128.append(stri[128*(len(stri)//128):]+(120-len(stri[128*(len(stri)//128):]))*'0')  #用0填充
        Plaintext_128[-1]=Plaintext_128[-1]+bin(m-8).replace('0b','0'*(10-len(bin(m-8))))     #最后8bit存放填放0的个数
    return Plaintext_128

#L线性变换 接收 l:字符串 返回32bit字符串
def L(l):
    C=bin(int(l,2)^int((l[2:]+l[0:2]),2)^int((l[10:]+l[0:10]),2)^int((l[18:]+l[0:18]),2)^int((l[24:]+l[0:24]),2))
    #C=B^(B<<<2)^(B<<<10)^(B<<<18)^(B<<<24)
    C=C.replace('0b','')
    if len(C)<32:
        C='0'*(32-len(C))+C
    return C

#L'线性变换 接收 l:字符串 返回32bit字符串
def L_1(l):
    C=bin(int(l,2)^int((l[13:]+l[0:13]),2)^int((l[23:]+l[0:23]),2))
    #C=B^(B<<<13)^(B<<<23)
    C=C.replace('0b','')
    if len(C)<32:
        C='0'*(32-len(C))+C
    return C

#T置换  s:字符串 L:线性变换函数 返回32位bit字符串
def T_Display(s,L):
    s=s.replace('0b','')
    if len(s)<32:
        s_bit = '0'*(32-len(s))+s
    else:
        s_bit = s
    a0,a1,a2,a3 = s_bit[0:8],s_bit[8:16],s_bit[16:24],s_bit[24:32]
    B = [S[int(a0[0:4],2)][int(a0[4:8],2)],S[int(a1[0:4],2)][int(a1[4:8],2)],
        S[int(a2[0:4],2)][int(a2[4:8],2)],S[int(a3[0:4],2)][int(a3[4:8],2)]]
    B_str=''
    for i in B:
        j=bin(i).replace('0b','')
        if len(j)<8:
            j='0'*(8-len(j))+j
        B_str=B_str+j
    C=L(B_str)
    return C

#密钥拓展 key:字符串 返回字符串列表
def Key_Expansion(key):
    if len(key)<16:
        key=key+'0'*(16-len(key))
    elif len(key)>16:
        key=key[0:16]
    key_bit = Str2bit(key)  #128bit密钥
    SK=[key_bit[0:32],key_bit[32:64],key_bit[64:96],key_bit[96:128]]
    K=list(range(0,36))
    K[0],K[1],K[2],K[3]=bin(int(SK[0],2)^FK[0]).replace('0b',''),\
    bin(int(SK[1],2)^FK[1]).replace('0b', ''),\
    bin(int(SK[2],2)^FK[2]).replace('0b',''),\
    bin(int(SK[3],2)^FK[3]).replace('0b','')
    RK=list(range(0,32))
    for i in range(32):
        s=bin(int(K[i+1],2)^int(K[i+2],2)^int(K[i+3],2)^CK[i])
        RK[i]=K[i+4]=bin(int(K[i],2)^int(T_Display(s,L_1),2))
    for i in range(32):
        RK[i]=RK[i].replace('0b','')
        RK[i]='0'*(32-len(RK[i]))+RK[i]
    return RK

#加密函数 plaintext,RK:字符串列表 返回字符串列表
def Encrypt(plaintext,RK):
    X=list(range(36))
    Y=list(range(4))
    ciphertext_list = []
    for i in plaintext:
        X[0],X[1],X[2],X[3] = i[0:32],i[32:64],i[64:96],i[96:128]
        for i in range(32):
            s=bin(int(X[i+1],2)^int(X[i+2],2)^int(X[i+3],2)^int(RK[i],2))
            X[i+4]=bin(int(X[i],2)^int(T_Display(s,L),2))
        for i in range(36):
            X[i]=X[i].replace('0b','')
            X[i]='0'*(32-len(X[i]))+X[i]
        ciphertext_list.extend([X[35],X[34],X[33],X[32]])
    ciphertext_list = ''.join(ciphertext_list)
    ciphertext_show = []
    ciphertext_str = ''
    for i in range(0,len(ciphertext_list)//8):
        ciphertext_show.append(ciphertext_list[i*8:8+i*8])
    for i in ciphertext_show:
        ciphertext_str=ciphertext_str+chr(int(i,2))
    return ciphertext_str

#解密函数 ciphertext,RK:字符串列表 返回字符串列表
def Decrypt(ciphertext,RK):
    X = list(range(36))
    Y = list(range(4))
    plaintext_list = []
    for i in ciphertext:
        X[0], X[1], X[2], X[3] = i[0:32], i[32:64], i[64:96], i[96:128]
        for i in range(32):
            s = bin(int(X[i + 1], 2) ^ int(X[i + 2], 2) ^ int(X[i + 3], 2) ^ int(RK[31-i], 2))
            X[i + 4] = bin(int(X[i], 2) ^ int(T_Display(s, L),2))
        for i in range(36):
            X[i]=X[i].replace('0b','')
            X[i]='0'*(32-len(X[i]))+X[i]
        plaintext_list.extend([X[35], X[34], X[33], X[32]])
    plaintext = []
    # 把生成的字符串每八位分成一段
    for i in plaintext_list:
        plaintext.extend([i[0:8],i[8:16],i[16:24],i[24:32]])
    n = int(plaintext[-1], 2)  # 从最后一段取出填充的‘0’的个数
    # 如果n=0 那么没有填充 直接删去最后一段
    if n == 0:
        plaintext.pop(-1)
    else:
        plaintext_1 = plaintext[::-1]  # 倒序存放
        plaintext_1.pop(0)  # 把最后一段拿掉
        number = 0  # 统计出现的0的个数
        k = 0  # 标记列表里的下标
        for i in plaintext_1:
            k = k + 1
            if i.count('0') != 8:  # 如果一段里的8位不全为0，那肯定不是填充的0 退出循环
                break
            else:
                number = number + 8
        if number == n:
            del plaintext[len(plaintext_1) - k + 1:]  # 当判断得到的0与n相等时，删除填充的0
    plaintext_str=''
    for i in plaintext:
        plaintext_str=plaintext_str+chr(int(i,2))
    return plaintext_str

