#!/usr/bin/env python
#-*- coding:utf-8 -*-
from tkinter import *
import tkinter.messagebox
import Fuctions
from tkinter import filedialog
import os
import base64

'''
    16271120
    马天波
    SMS4密码实验
'''

global file_mw #定义全局变量 来接收文件中的明文/密文
file_mw = ''

global file_name #全局变量 文件名
file_name = ''

global file_suffix  #全局变量 后缀名
file_suffix =''

#加密函数
def mtb_jiami():
    if miyao.get() == '':
        tkinter.messagebox.showerror('错误', "请输入密钥")
        raise SystemError("没有输入密钥")
    else:
        l=[]
        for i in miyao.get():
            l.append(ord(i))
        for i in l:
            if not 0<=i<128:
                tkinter.messagebox.showerror('错误', "密钥输入有误")
                raise SystemError("密钥输入错误")
    mw2.delete('1.0', 'end')
    key=miyao.get()
    KEY=Fuctions.Key_Expansion(key)
    mingwen=mw1.get('1.0','end')
    if len(mingwen) <= 1:
        tkinter.messagebox.showerror('错误', '没有输入明文')
        raise SystemError('没有输入明文')
    mingwen = mingwen.replace('\n', '')
    mingwen = str(base64.b64encode(mingwen.encode('utf-8')),'utf-8')
    mw_list = Fuctions.Divide_128(mingwen)
    miwen = Fuctions.Encrypt(mw_list,KEY)
    miwen = str(base64.b64encode(miwen.encode('utf-8')),'utf-8')
    mw2.insert('1.0',miwen)

def file_jiami():
    if miyao.get() == '':
        tkinter.messagebox.showerror('错误', "请输入密钥")
        raise SystemError("没有输入密钥")
    else:
        l=[]
        for i in miyao.get():
            l.append(ord(i))
        for i in l:
            if not 0<=i<128:
                tkinter.messagebox.showerror('错误', "密钥输入有误")
                raise SystemError("密钥输入错误")
    key = miyao.get()
    KEY = Fuctions.Key_Expansion(key)
    mingwen = file_mw
    if len(mingwen) <= 1:
        tkinter.messagebox.showerror('错误', '没有选择文件')
        raise SystemError('没有选择文件')
    if len(mw5.get()) <= 1:
        tkinter.messagebox.showerror('错误','没有选择保存路径')
        raise SystemError('没有选择保存路径')
    mingwen = mingwen.replace('\n', '')
    mw_list = Fuctions.Divide_128(mingwen)
    miwen = Fuctions.Encrypt(mw_list,KEY)
    path = path_2.get()
    miwen_b = base64.b64encode(miwen.encode('utf-8'))
    with open(path+'/'+file_name.replace(file_suffix,'')+'_Encrypt'+file_suffix,'wb') as f:
        f.write(miwen_b)

#解密函数
def mtb_jiemi():
    if miyao.get() == '':
        tkinter.messagebox.showerror('错误', "请输入密钥")
        raise SystemError("没有输入密钥")
    else:
        l=[]
        for i in miyao.get():
            l.append(ord(i))
        for i in l:
            if not 0<=i<128:
                tkinter.messagebox.showerror('错误', "密钥输入有误")
                raise SystemError("密钥输入错误")
    mw1.delete('1.0','end')
    key = miyao.get()
    KEY = Fuctions.Key_Expansion(key)
    miwen=mw2.get('1.0','end')
    if len(miwen) <= 1:
        tkinter.messagebox.showerror('错误', '没有输入密文')
        raise SystemError('没有输入密文')
    miwen = (base64.b64decode(bytes(miwen,'utf-8'))).decode('utf-8')
    miwen = Fuctions.Divide_128(miwen)
    mingwen = Fuctions.Decrypt(miwen,KEY)
    mingwen = (base64.b64decode(bytes(mingwen,'utf-8'))).decode('utf-8')
    mw1.insert('1.0',mingwen)

def file_jiemi():
    if miyao.get() == '':
        tkinter.messagebox.showerror('错误', "请输入密钥")
        raise SystemError("没有输入密钥")
    else:
        l=[]
        for i in miyao.get():
            l.append(ord(i))
        for i in l:
            if not 0<=i<128:
                tkinter.messagebox.showerror('错误', "密钥输入有误")
                raise SystemError("密钥输入错误")
    key = miyao.get()
    KEY = Fuctions.Key_Expansion(key)
    miwen = file_mw
    miwen = bytes(file_mw,encoding='utf-8')
    miwen = base64.b64decode(miwen)
    miwen = base64.b64decode(miwen)
    miwen = miwen.decode('utf-8')
    if len(miwen) <= 1:
        tkinter.messagebox.showerror('错误', '没有选择文件')
        raise SystemError('没有选择文件')
    if len(mw5.get()) <= 1:
        tkinter.messagebox.showerror('错误','没有选择保存路径')
        raise SystemError('没有选择保存路径')
    miwen = Fuctions.Divide_128(miwen)
    mingwen = Fuctions.Decrypt(miwen,KEY)
    mingwen_b = mingwen.encode('utf-8')
    mingwen_b = base64.b64decode(mingwen_b)
    path = path_2.get()
    with open(path+'/'+file_name.replace(file_suffix,'')+'_Decrypt'+file_suffix,'wb') as f:
        f.write(mingwen_b)

#清空函数
def qingkong():
    mw1.delete('1.0', 'end')
    mw2.delete('1.0', 'end')
    mw3.delete('0', 'end')

#打开文件
def openfile():
    global file_mw  #声明全局变量
    file_mw=''      #初始赋值为空
    global file_suffix
    file_suffix = ''
    global file_name
    file_name  = ''
    mw4.delete('0', 'end')
    fname=filedialog.askopenfilename()
    mw4.insert('0',fname)
    file_suffix = os.path.splitext(fname)[1]    #获取文件后缀名
    file_name = os.path.split(fname)[1]
    with open(fname,'rb') as f:         #文件以二进制模式读取
        file_mw = str(base64.b64encode(f.read()),'utf-8')

#选择保存文件路径
def choose_path():
    mw5.delete('0','end')
    fname=filedialog.askdirectory()
    mw5.insert('0',fname)

root=Tk()
root.title("SMS4")
root.geometry("760x315")
root.resizable(width=False, height=FALSE)
Label(root,text='SMS4加密解密程序',width=15,height=2).place(x=300,y=0)
Label(root,text="明文",width=5,height=2).place(x=10,y=25)
Label(root,text="密钥",width=9,height=2).place(x=10,y=200)
Label(root,text="密文",width=5,height=2).place(x=385,y=25)
Label(root,text='文件路径',width=10,height=2).place(x=5,y=235)
Label(root,text='保存路径',width=10,height=2).place(x=5,y=270)
miyao = StringVar()
path_1 = StringVar()
path_2 = StringVar()
mw1 = Text(root,width=50,height=10)
mw1.place(x=15,y=60)
mw2 = Text(root,width=50,height=10)
mw2.place(x=390,y=60)
mw3 = Entry(root,textvariable=miyao,width=40)
mw3.place(x=75,y=210)
mw4 = Entry(root,textvariable=path_1,width=40)
mw4.place(x=75,y=245)
mw5 = Entry(root,textvariable=path_2,width=40)
mw5.place(x=75,y=280)
Button(root,text="加密",width=15,command=mtb_jiami).place(x=385,y=205)
Button(root,text="解密",width=15,command=mtb_jiemi).place(x=520,y=205)
Button(root,text="清空",width=10,command=qingkong).place(x=655,y=205)
Button(root,text='打开',width=15,command=openfile).place(x=385,y=240)
Button(root,text='选择',width=15,command=choose_path).place(x=385,y=275)
Button(root,text='文件加密',width=20,command=file_jiami).place(x=520,y=240)
Button(root,text='文件解密',width=20,command=file_jiemi).place(x=520,y=275)
root.mainloop()