'''
    File name: IG_Unpinner.py
    Author: Nicolas Tremblay (https://github.com/EquiFox)
    Date created: 10/8/2017
    Version: 2.0.0

    Utility used to patch Instagram's APKs in order to disable Certificate Pinning protection.
'''

import os
import sys
import subprocess
import re
import shutil
import binascii
from colorama import init as colorama_init
from colorama import Fore

active_dir = os.path.dirname(os.path.realpath(sys.argv[0])) + '/'
output_dir = ''
project_name = ''
work_dir = ''
colorama_init()

def call(cmd, **kwargs):
    print('Running: {0}'.format(' '.join(cmd)))
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    out, err = p.communicate()


def print_header(text):
    sys.stdout.write(Fore.YELLOW)
    block = "********************************************"
    print('\n' + block)
    print('**' + text.center(len(block) - 4) + '**')
    print(block)
    sys.stdout.write(Fore.RESET)


def print_success(text):
    sys.stdout.write(Fore.GREEN)
    print(text)
    sys.stdout.write(Fore.RESET)


def print_step(text):
    sys.stdout.write(Fore.CYAN)
    print(text)
    sys.stdout.write(Fore.RESET)


def print_error(text):
    sys.stdout.write(Fore.RED)
    print(text)
    sys.stdout.write(Fore.RESET)


def decode_apk(apkFile):
    call(['java', '-jar', active_dir + 'Tools/apktool.jar', 'd', apkFile, '-o', work_dir, '-f'])
    print_success("APK Decoded !")


def extract_package_name():
    pattern = re.compile('package="(.*?)"')

    with open(work_dir + '/AndroidManifest.xml') as manifestFile:
        for i, line in enumerate(manifestFile):
            for match in re.finditer(pattern, line):
                return match.group(1)
    return ""


def extract_instagram_version():
    pattern = re.compile("  versionCode: '(.*)'\n  versionName: (.*)")

    with open(work_dir + '/apktool.yml') as metadataFile:
        apk_metadata = metadataFile.read()
        match = re.findall(pattern, apk_metadata)

        if match:
            return match[0][1] + " (" + match[0][0] + ")"

    return "Unknown Version"


def keystore_patch(file_handle, code):
    try:
        i = code.index(".method public static b()Ljavax/net/ssl/SSLContext;\n")
        code.insert(i + 47, "    const/4 v4, 0x0\n\n")

        file_handle.seek(0)
        file_handle.writelines(code)
        return True
    except ValueError:
        pass

    return False


def cert_validation_patch(file_handle, code):
    try:
        i = code.index(".method public final a(Ljava/lang/String;[Ljava/security/cert/Certificate;)V\n")
        code.insert(i + 4, "    return-void\n\n")

        file_handle.seek(0)
        file_handle.writelines(code)
        return True
    except ValueError:
        pass

    return False


def zero_protocol_patch(file_handle, code):
    try:
        code.index(".class public Lcom/facebook/proxygen/ZeroProtocolSettings;\n")
        code[29] = "    .locals 1"

        code.insert(36, "    const/4 v0, 0x0\n\n")
        code[37] = code[37].replace("iput-boolean p1, p0", "iput-boolean v0, p0")

        code.insert(61, "    const/4 v0, 0x1\n\n")
        code[62] = code[62].replace("iput p9, p0", "iput v0, p0")

        file_handle.seek(0)
        file_handle.writelines(code)
        return True
    except ValueError:
        pass

    return False


def ssl_session_patch(file_handle, code):
    try:
        i = code.index(".method public final verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z\n")

        if "getPeerCertificates" in code[i + 8]:
            var_index = re.search('const\/4 (.*?), 0x0', code[i + 4])
            code.insert(i + 6, "    return {}\n\n".format(var_index.group(1)))

            file_handle.seek(0)
            file_handle.writelines(code)
            return True
    except ValueError:
        pass

    return False


def connection_drop_patch(file_handle, code):
    try:
        i = code.index(".method public final close()V\n")

        if code[i + 1] == "    .locals 6\n":
            code.insert(i + 7, "    return-void\n\n")

            file_handle.seek(0)
            file_handle.writelines(code)
            return True
    except ValueError:
        pass

    return False


def arm32_ssl_verify_patch(project_folder):
    lib_path = project_folder + '/lib/armeabi-v7a/libsslx.so'

    if not os.path.isfile(lib_path):
        lib_path = project_folder + '/lib/armeabi-v7a/libliger.so'

    with open(lib_path, "rb+") as libFile:
        bytes = libFile.read()
        hex_string = binascii.hexlify(bytes)
        method_offset = hex_string.find("c0f8c8100ab1c0f8cc207047")

        if method_offset != -1:
            bytes = binascii.unhexlify(hex_string.replace("c0f8c8100ab1c0f8cc207047", "c0f8c83001e0c0f8cc207047"))

            libFile.seek(0)
            libFile.write(bytes)
            return True
    return False


def x86_ssl_verify_patch(project_folder):
    lib_path = project_folder + '/lib/x86/libsslx.so'

    if not os.path.isfile(lib_path):
        lib_path = project_folder + '/lib/x86/libliger.so'

    with open(lib_path, "rb+") as lib_file:
        bytes = lib_file.read()
        hex_string = binascii.hexlify(bytes)
        method_offset = hex_string.find("85d28988c8000000740689")

        if method_offset != -1:
            bytes = binascii.unhexlify(hex_string.replace("85d28988c8000000740689", "c780c800000000000000c3"))

            lib_file.seek(0)
            lib_file.write(bytes)
            return True
    return False


def native_ssl_verify_patch(project_folder):
    if not os.path.isdir(work_dir + "/lib/x86/"):
        return arm32_ssl_verify_patch(project_folder)
    else:
        return x86_ssl_verify_patch(project_folder)


def apply_patches():
    print_header("Applying Modifications")

    smali_files = [os.path.join(dp, f) for dp, dn, fileNames in os.walk(work_dir + '/smali/com') for f in fileNames]
    success_cpt = 0

    for smali_file in smali_files:
        with open(smali_file, "r+") as smali_code:
            lines = smali_code.readlines()

            if keystore_patch(smali_code, lines):
                print_step(" ==> Prevented Keystore Initialization !")
                success_cpt += 1
                continue

            if cert_validation_patch(smali_code, lines):
                print_step(" ==> Authorized Any Certificate !")
                success_cpt += 1
                continue

            if zero_protocol_patch(smali_code, lines):
                print_step(" ==> Disabled ZeroProtocol Policy !")
                success_cpt += 1
                continue

            if ssl_session_patch(smali_code, lines):
                print_step(" ==> Disabled SSL Session Validation !")
                success_cpt += 1
                continue

            if connection_drop_patch(smali_code, lines):
                print_step(" ==> Prevented Connection Dropping !")
                success_cpt += 1
                continue

        if success_cpt >= 5:
            break

    if native_ssl_verify_patch(work_dir):
        print_step(" ==> Disabled Native OpenSSL Verification !")
        success_cpt += 1

    return success_cpt >= 6


def rebuild(output_file):
    print_header("Rebuilding APK")

    if os.path.isfile(output_file):
        os.remove(output_file)

    print_success("Repackaging...")
    call(['java', '-jar', active_dir + 'Tools/apktool.jar', 'b', work_dir, '-o', output_file])

    print_success("Signing...")
    call(['java', '-jar', '"' + active_dir + 'Tools/apksigner.jar"', 'sign', '--ks', '"' + active_dir + 'Tools/UnpinnerKey.jks"',
          '--ks-pass', 'pass:Hannah123', '--key-pass', 'pass:Hannah123', '"' + output_file + '"'])

    print_success("Completed !")


def main():
    global active_dir, output_dir, project_name, work_dir

    if len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        print_header("Decoding APK file")
        apk_file = sys.argv[1]
        output_dir = os.path.dirname(os.path.realpath(sys.argv[1])) + '/'
        project_name = os.path.splitext(os.path.basename(apk_file))[0]
        work_dir = output_dir + project_name

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        decode_apk(apk_file)
        package_name = extract_package_name()

        if package_name == 'com.instagram.android':
            version = extract_instagram_version()
            print_success("======> Instagram " + version + " <======")

            if apply_patches():
                print_success("All Patches Applied !")

                file_name = work_dir + "-UNPINNED.apk"
                rebuild(file_name)
            else:
                print_error("Unable to apply all modifications...")
        else:
            print_error("The provided APK (" + package_name + ") isn't Instagram...")

        shutil.rmtree(work_dir)
    else:
        print_error("Please provide a valid path to an Instagram APK file !")


if __name__ == "__main__":
    main()
