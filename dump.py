#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import sys
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import paramiko
import frida
import threading
import platform
from tqdm import tqdm
import traceback

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))
DUMP_JS = os.path.join(script_dir, 'dump.js')

User = 'root'
Password = 'alpine'
Host = 'localhost'
Port = 2222
KeyFileName = None

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()

def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed(): changed.set()
    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]
    device_manager.off('changed', on_changed)
    return device

def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'
    print('\nGenerating "{}"...'.format(ipa_filename))
    try:
        app_name = file_dict.get('app')
        if not app_name:
            print("[!] 未找到主程序目录，打包可能失败！")
            return

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app' and os.path.exists(from_dir):
                if not os.path.exists(os.path.dirname(to_dir)):
                    os.makedirs(os.path.dirname(to_dir))
                shutil.move(from_dir, to_dir)

        output_zip = os.path.join(os.getcwd(), display_name)
        shutil.make_archive(output_zip, 'zip', TEMP_DIR, PAYLOAD_DIR)
        
        if os.path.exists(ipa_filename):
            os.remove(ipa_filename)
        os.rename(output_zip + '.zip', ipa_filename)

        shutil.rmtree(PAYLOAD_PATH)
        print('\n[+] 砸壳完成！文件已保存为: {}'.format(ipa_filename))
    except Exception as e:
        print("\n[!] 打包 IPA 时发生错误:", e)
    finally:
        finished.set()

def sftp_get_recursive(sftp, remote_path, local_dir, progress_bar, last_sent_list):
    import stat
    basename = os.path.basename(remote_path.rstrip('/'))
    local_path = os.path.join(local_dir, basename)
    
    try:
        mode = sftp.stat(remote_path).st_mode
    except IOError as e:
        return

    if stat.S_ISDIR(mode):
        if not os.path.exists(local_path):
            os.makedirs(local_path)
        try:
            for item in sftp.listdir(remote_path):
                sftp_get_recursive(sftp, remote_path + '/' + item, local_path, progress_bar, last_sent_list)
        except Exception as e:
            print("\n[!] 读取目录失败:", e)
    else:
        last_sent_list[0] = 0
        progress_bar.desc = basename.decode("utf-8", errors="ignore") if IS_PY2 or isinstance(basename, bytes) else basename
            
        try:
            progress_bar.total = sftp.stat(remote_path).st_size
        except:
            progress_bar.total = 0
            
        def sftp_progress(transferred, total):
            if total > 0:
                progress_bar.total = total
            progress_bar.update(transferred - last_sent_list[0])
            last_sent_list[0] = transferred

        try:
            sftp.get(remote_path, local_path, callback=sftp_progress, prefetch=False)
        except Exception as e:
            print("\n[!] 下载文件失败:", e)

def on_message(message, data):
    if message.get('type') == 'error':
        print("\n[!] Frida 引擎底层崩溃: " + str(message.get('description', '')))
        finished.set()
        return

    if message.get('type') == 'log':
        print("[*] 手机端日志: " + str(message.get('payload', '')))
        return

    if message.get('type') == 'send':
        payload = message.get('payload')
        if not isinstance(payload, dict):
            return
            
        if payload.get('type') == 'error':
            print("\n[!] 手机端 JS 脚本执行失败:")
            print(" -> 错误详情: " + str(payload.get('description', '')))
            print(" -> 错误堆栈: \n" + str(payload.get('stack', '')))
            finished.set()
            return
            
        t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1, leave=False)
        last_sent = [0]
        try:
            if 'dump' in payload:
                origin_path = payload['path']
                dump_path = payload['dump']

                sftp = ssh.open_sftp()
                sftp_get_recursive(sftp, dump_path, PAYLOAD_PATH, t, last_sent)
                sftp.close()

                if platform.system() != 'Windows':
                    try: subprocess.check_call(('chmod', '655', os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))))
                    except: pass 

                index = origin_path.find('.app/')
                file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

            if 'app' in payload:
                app_path = payload['app']

                sftp = ssh.open_sftp()
                sftp_get_recursive(sftp, app_path, PAYLOAD_PATH, t, last_sent)
                sftp.close()

                if platform.system() != 'Windows':
                    try: subprocess.check_call(('chmod', '755', os.path.join(PAYLOAD_PATH, os.path.basename(app_path))))
                    except: pass

                file_dict['app'] = os.path.basename(app_path)

            if 'done' in payload:
                finished.set()
        except Exception as e:
            print("\n[!] 传输发生严重异常:", e)
            finished.set()
        finally:
            t.close()

def get_applications(device):
    try:
        return device.enumerate_applications()
    except Exception as e:
        sys.exit('Failed to enumerate apps: %s' % e)

# 恢复应用列表排序与格式化打印功能
def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        if a.name > b.name: return 1
        elif a.name < b.name: return -1
        else: return 0
    elif a_is_running: return -1
    else: return 1

def cmp_to_key(mycmp):
    class K:
        def __init__(self, obj, *args):
            self.obj = obj
        def __lt__(self, other): return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other): return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other): return mycmp(self.obj, other.obj) == 0
        def __le__(self, other): return mycmp(self.obj, other.obj) <= 0
        def __ge__(self, other): return mycmp(self.obj, other.obj) >= 0
        def __ne__(self, other): return mycmp(self.obj, other.obj) != 0
    return K

def list_applications(device):
    applications = get_applications(device)
    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len(str(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0

    pid_column_width = max(pid_column_width, 3)
    name_column_width = max(name_column_width, 4)
    identifier_column_width = max(identifier_column_width, 10)

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(identifier_column_width) + 's'
    
    for application in sorted(applications, key=cmp_to_key(compare_applications)):
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format % (application.pid, application.name, application.identifier))

def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))
    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for app in get_applications(device):
        if name_or_bundleid in (app.identifier, app.name):
            pid, display_name, bundle_identifier = app.pid, app.name, app.identifier

    is_spawned = False
    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            is_spawned = True
        else:
            session = device.attach(pid)
    except Exception as e:
        print(e) 
    return session, display_name, bundle_identifier, pid, is_spawned

def start_dump(session, ipa_name, device, app_pid, is_spawned):
    print('Dumping {} to {}'.format(ipa_name, TEMP_DIR))
    source = ''
    with open(DUMP_JS, 'r', encoding='utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    
    if is_spawned:
        device.resume(app_pid)
        
    script.post('dump')
    finished.wait()
    generate_ipa(PAYLOAD_PATH, ipa_name)
    if session:
        session.detach()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (Fixed Lifecycle)')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='ssh_host', help='Specify SSH hostname')
    parser.add_argument('-p', '--port', dest='ssh_port', help='Specify SSH port')
    parser.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username')
    parser.add_argument('-P', '--password', dest='ssh_password', help='Specify SSH password')
    parser.add_argument('-K', '--key_filename', dest='ssh_key_filename', help='Specify SSH private key file path')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')

    args = parser.parse_args()
    exit_code = 0
    ssh = None

    device = get_usb_iphone()

    # 拦截 -l 参数，展示列表后直接退出
    if args.list_applications:
        list_applications(device)
        sys.exit(0)

    # 必须在 -l 检测之后再判断 target 是否为空，否则会导致只输入 -l 时报错退出
    if not args.target:
        parser.print_help()
        sys.exit(0)

    if args.ssh_host: Host = args.ssh_host
    if args.ssh_port: Port = int(args.ssh_port)
    if args.ssh_user: User = args.ssh_user
    if args.ssh_password: Password = args.ssh_password
    if args.ssh_key_filename: KeyFileName = args.ssh_key_filename

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(Host, port=Port, username=User, password=Password, key_filename=KeyFileName)

        if os.path.exists(PAYLOAD_PATH): shutil.rmtree(PAYLOAD_PATH)
        os.makedirs(PAYLOAD_PATH)
        
        session, display_name, bundle_identifier, app_pid, is_spawned = open_target_app(device, args.target)
        output_ipa = re.sub(r'\.ipa$', '', args.output_ipa or display_name)
        
        if session:
            start_dump(session, output_ipa, device, app_pid, is_spawned)
            
    except Exception as e:
        print('\n*** Caught exception: %s: %s' % (e.__class__.__name__, e))
        exit_code = 1
    finally:
        if ssh: ssh.close()
        if os.path.exists(PAYLOAD_PATH): shutil.rmtree(PAYLOAD_PATH)
        sys.exit(exit_code)