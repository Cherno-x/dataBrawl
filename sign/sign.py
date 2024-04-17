import os
from time import sleep
from sign import sigthief
import subprocess

def callResHacker(target_file, source_file,result_file):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        os.chdir(script_dir)
        subprocess.run(f"ResourceHacker.exe -open \"{source_file}\" -save source.res -action extract -mask ICONGROUP,VERSION INFO,MAINFEST,", shell=True, check=True)
        sleep(3)
        subprocess.run(f"ResourceHacker.exe -open \"{target_file}\" -action addskip -res source.res -save \"{result_file}\"", shell=True, check=True)
        
        print("资源添加成功")
    except FileNotFoundError as e:
        print(f"错误: 文件未找到 - {e}")
    except subprocess.CalledProcessError as e:
        print(f"错误: 调用进程失败 - {e}")

def callSigthief(temp_file,source_file,result_file):
    targetfile = temp_file
    outputfile = result_file
    cert = sigthief.copyCert(source_file)
    sigthief.writeCert(cert, targetfile, outputfile)
