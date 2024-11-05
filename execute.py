import os
import subprocess
import tempfile
import re
import asyncio
import uuid

import aiofiles
import shlex
from pathlib import Path
from wakeonlan import send_magic_packet
from fabric import Connection
from paramiko import AuthenticationException
from paramiko.ssh_exception import NoValidConnectionsError, SSHException

from data import is_ip_valid, save_data, get_data_dict


def get_tempfile() -> str:
    with tempfile.NamedTemporaryFile(delete=False) as file:
        file_name = file.name
    return file_name


def is_ip_online(ip: str) -> bool:
    file_name = get_tempfile()
    if not is_ip_valid(ip):
        print('invalid ip')
        return False
    proc = subprocess.run(f'ping {ip} -c 2 > {file_name}', shell=True, stdout=subprocess.PIPE)
    if proc.returncode:
        return False
    online = False
    with open(file_name, mode='r') as file:
        ping_output = file.read()
    if 'ttl=' in ping_output.lower():
        online = True
    file = Path(file_name)
    file.unlink(missing_ok=True)
    return online


async def async_is_ip_online(ip: str) -> bool:
    file_name = get_tempfile()
    if not is_ip_valid(ip):
        print('invalid ip')
        return False
    proc = await asyncio.create_subprocess_shell(
        f'ping {ip} -c 2 > {file_name}',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode:
        return False
    online = False
    async with aiofiles.open(file_name, mode='r') as file:
        ping_output = await file.read()
    if 'ttl=' in ping_output.lower():
        online = True
    file = Path(file_name)
    file.unlink(missing_ok=True)
    return online


def get_mac(ip_address):
    # Пингуем устройство, чтобы обновить ARP таблицу
    ping_response = subprocess.run(f"ping -c 1 {ip_address}", shell=True, stdout=subprocess.PIPE).returncode

    if ping_response == 0:
        # Используем команду arp для получения MAC-адреса
        output = subprocess.check_output(f"arp -a {ip_address}", shell=True, encoding='cp866')

        # Ищем строку с MAC-адресом
        mac_address = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)

        if mac_address:
            return mac_address.group(0)
        else:
            return None
    else:
        return None


decode_to = 'cp65001'


def wake_on_lan(ip_address: str) -> bool:
    saved_data = get_data_dict()
    if saved_data['ips'][ip_address]['mac']:
        mac_address = saved_data['ips'][ip_address]['mac']
    else:
        mac_address = get_mac(ip_address)
        if not mac_address:
            print('no mac')
            return False
        else:
            saved_data['ips'][ip_address]['mac'] = mac_address
            save_data(saved_data)
    print(ip_address, mac_address)
    try:
        send_magic_packet(mac_address)
        print('sent to', ip_address)
        return True
    except Exception as e:
        print(e)
        return False


def start_process_paexec(remote_ip, username, password, command, interactive=False):
    file_name = get_tempfile()

    # Команда для запуска процесса на удалённой машине
    paexec_command = [
        'paexec.exe', '\\\\' + remote_ip
    ]
    if username and password:
        paexec_command += [
            '-u', username,
            '-p', password
        ]
    if interactive:
        paexec_command.append('-i')
    paexec_command += [
        '-d',  # -d указывает на запуск в качестве фонового процесса
        '-lo', file_name,  # -lo сохраняет стандартный вывод в файл
        *shlex.split(command)
    ]
    print('paexec command', paexec_command)
    process = subprocess.run(paexec_command, stdout=subprocess.PIPE)
    print(process)
    with open(file_name, mode='r', encoding='utf-8') as file_with_data:
        text = file_with_data.read()
        pid = re.findall('started with process ID (\\d+)', text)
        if pid:
            pid = pid[0]
    file = Path(file_name)
    file.unlink(missing_ok=True)
    if process.returncode == 0:
        return pid
    else:
        error = re.findall('Returned error:\n  ([a-zA-Zа-яА-Я ."]+) ', text)
        if error and len(error) == 1:
            print(f"Error starting process: {error[0]}")
        return None


def get_connection(host: str, username: str, password: str = None, ssh_key: str = None, port: int = 22, ssh_use_key: bool = False):
    """
    Establishes a connection to a remote host.

    Parameters
    ----------
    host : str
        The hostname or IP address of the remote host.
    username : str
        The username to use for the connection.
    password : str, optional
        The password to use for password authentication.
    ssh_key : str, optional
        The path to the SSH key to use for key authentication.
    port : int, optional
        The port to use for the connection. Defaults to 22.
    ssh_use_key : bool, optional
        Whether to use SSH key authentication. Defaults to False.

    Returns
    -------
    conn : Connection
        A Connection object representing the established connection.

    Raises
    ------
    ValueError
        If either password or SSH key authentication fails, or if no valid
        connection can be established.
    """
    if not port:
        port = 22
    print(ssh_use_key, password, ssh_key)
    if not ssh_use_key and password:
        conn = Connection(host=host, user=username, connect_kwargs={"password": password}, port=port)
    elif ssh_use_key and ssh_key:
        ssh_key_path = os.path.join(os.getcwd(), 'keys', host, ssh_key)
        if not os.path.exists(ssh_key_path):
            raise ValueError(f"SSH key {ssh_key} not found")
        conn = Connection(host=host, user=username, connect_kwargs={"key_filename": ssh_key_path})
    else:
        raise ValueError("Must provide either password or SSH key")

    try:
        conn.open()
    except NoValidConnectionsError as e:
        raise ValueError(f'Connect error: {e}')
    except AuthenticationException as e:
        if ssh_use_key:
            raise ValueError(f'Authentication failed: key auth failed')
        elif password:
            raise ValueError(f'Authentication failed: password auth failed')
    except ValueError:
        if not password and ssh_key:
            raise ValueError(f'Connect error: No user {username} or key auth failed')
        elif password:
            raise ValueError(f'Connect error: No user {username}')
    return conn


# powershell (Start-Process "notepad.exe" -PassThru).id

def get_remote_os_and_device_name(conn: Connection):
    """
    Establishes a connection to a remote host and determines the remote OS and device name.

    Parameters
    ----------
    conn : Connection
        A Connection object representing the established connection.

    Returns
    -------
    tuple
        A tuple containing the remote OS type (str) and device name (str).

    Raises
    ------
    ValueError
        If the connection cannot be established, or if the remote OS type
        cannot be determined.
    """
    ssh_proc = None
    os_type = None
    # Get OS type
    try:
        ssh_proc = conn.run('uname -s', hide=True, warn=True)
    except SSHException as e:
        raise ValueError(f'Connect error: Channel closed')
    ssh_proc = ssh_proc.stdout.strip()
    if ssh_proc in ["Linux", "Android"]:
        os_type = "Linux" #if os_type != "Android" else "Android"
    elif ssh_proc == 'Darwin':
        os_type = 'MacOS'
    if not os_type:
        try:
            # Try to run a command that is common to Windows systems
            ssh_proc = conn.run("ver", hide=True, warn=True)
        except SSHException as e:
            raise ValueError(f'Connect error: Channel closed')
        if ssh_proc.stdout.strip().startswith("Microsoft Windows"):
            os_type = "Windows"
    if not os_type:
        try:
            # Try to run a command that is common to MacOS systems
            ssh_proc = conn.run("sw_vers", hide=True, warn=True)
        except SSHException as e:
            raise ValueError(f'Connect error: Channel closed')
        if ssh_proc.stdout.strip().startswith("ProductName: Mac OS X"):
            os_type = "MacOS"

    device_name = 'unknown'
    # Get device name
    if os_type in ('Linux', 'Windows', 'MacOS'):
        device_name = conn.run('hostname', hide=True, warn=True).stdout.strip()

    return os_type, device_name


def start_process_ssh(conn: Connection, command: str, os_type):
    """
    Starts a process on a remote system via SSH.

    Parameters
    ----------
    conn : Connection
        A Connection object representing the established connection.
    command : str
        The command to execute on the remote system.
    os_type : str
        The type of remote OS. Should be one of 'Linux', 'Windows', or 'MacOS'.

    Returns
    -------
    str
        The PID of the newly started process.

    Raises
    ------
    ValueError
        If the connection cannot be established, or if the remote process
        cannot be started.
    """
    ssh_command = None
    if os_type == 'Windows':
        user_response = conn.run('query user', hide=True, warn=True, encoding='cp866')
        print('user respinse', user_response)
        if conn.user not in user_response.stdout:
            raise ValueError(f'Login as {conn.user} in system first')

        temp_name = str(uuid.uuid4())

        # Without PID
        ssh_command = f'schtasks /create /tn "Laar-{temp_name}" /sc once /st 00:00 /f /tr "cmd.exe /C """cd %userprofile% ^&^& {command}""" " && schtasks /run /tn "Laar-{temp_name}"'

        print(ssh_command)
        response = conn.run(ssh_command, hide=True, warn=True, encoding='cp866')
        print('RESPONSE re_code:', response.return_code)
        print('RESPONSE stdout:', response.stdout)
        print('RESPONSE stderr:', response.stderr)
        if response.return_code or response.stderr:
            if response.stderr.strip():
                stderr = response.stderr.strip().split('\n')
                print(stderr)
                if not (len(stderr) == 1 and (stderr[0].startswith('Предупреждение') or stderr[0].startswith('Warning'))):
                    raise ValueError('Error starting process: ' + response.stderr.strip())
            elif response.stdout.strip():
                raise ValueError('Error starting process: ' + response.stdout.strip())
            else:
                raise ValueError('Error starting process')
        # pid_match = re.match(r'(\d+)', response.stdout.split()[-1])
        # if not pid_match:
        #     raise ValueError('Error starting process')
        # pid = pid_match.group(1)
        pid = ''
    else:
        if os_type == 'Linux':
            print('running on Linux: ', command)
            ssh_command = f'nohup {command} > /dev/null 2>&1 & echo $!'
        elif os_type == 'MacOS':
            ssh_command = f'osascript -e \'tell application "{command}" to activate\' & echo $!'
        pid_response = conn.run(ssh_command, hide=True, warn=True)
        if pid_response.return_code:
            if pid_response.stderr.strip():
                raise ValueError('Error starting process: ' + pid_response.stderr.strip())
            elif pid_response.stdout.strip():
                raise ValueError('Error starting process: ' + pid_response.stdout.strip())
            else:
                raise ValueError('Error starting process')
        pid_match = re.match(r'(\d+)', pid_response.stdout.strip())
        if not pid_match:
                raise ValueError('Error starting process')
        pid = pid_match.group(1)
    return pid


def start_process(command: str, saved_data: dict, ip: str) -> int:
    """
    Starts a process on a remote system via SSH or PAExec.

    Parameters
    ----------
    command : str
        The command to execute on the remote system.
    saved_data : dict
        A dictionary with saved data about the device.
    ip : str
        The IP address of the remote system.

    Returns
    -------
    int
        The PID of the newly started process.

    Raises
    ------
    ValueError
        If the connection cannot be established, or if the remote process
        cannot be started.
    """
    os_type = saved_data['ips'][ip]['os_type']
    username = saved_data['ips'][ip]['username']
    password = saved_data['ips'][ip]['password']
    ssh_use_key = saved_data['ips'][ip]['ssh_use_key']
    ssh_key = saved_data['ips'][ip]['ssh_key']
    connect_type = saved_data['ips'][ip]['connect_type']
    ssh_port = saved_data['ips'][ip]['ssh_port']
    pid = None
    print(os_type, username, password, ssh_key, connect_type)
    if not username or not password and not ssh_key:
        raise ValueError('Configure device')
    if connect_type == 'ssh':
        with get_connection(ip, username, password=password, ssh_key=ssh_key, port=ssh_port, ssh_use_key=ssh_use_key) as conn:
            if not os_type:
                os_type, device_name = get_remote_os_and_device_name(conn)
                saved_data['ips'][ip]['os_type'] = os_type
                saved_data['ips'][ip]['device_name'] = device_name
                save_data(saved_data)
            pid = start_process_ssh(conn, command, os_type)
    elif connect_type == 'paexec':
        pid = start_process_paexec(ip, username, password, command)
    else:
        raise ValueError('Unknown connect type')
    return pid


def kill_process(pid: str, saved_data: dict, ip: str) -> None:
    os_type = saved_data['ips'][ip]['os_type']
    username = saved_data['ips'][ip]['username']
    password = saved_data['ips'][ip]['password']
    ssh_key = saved_data['ips'][ip]['ssh_key']
    ssh_use_key = saved_data['ips'][ip]['ssh_use_key']
    connect_type = saved_data['ips'][ip]['connect_type']
    ssh_port = saved_data['ips'][ip]['ssh_port']

    if not username or not password and not ssh_key:
        raise ValueError('Configure device')
    for task in saved_data['tasks']:
        if task['pid'] == pid and task['ip'] == ip:
            break
    else:
        raise ValueError('Task not found')
    if connect_type == 'ssh':
        with get_connection(ip, username, password=password, ssh_key=ssh_key, port=ssh_port, ssh_use_key=ssh_use_key) as conn:
            kill_process_ssh(conn, pid, os_type)
    elif connect_type == 'paexec':
        kill_process_paexec(ip, username, password, pid)
    else:
        raise ValueError('Unknown connect type')
    saved_data['tasks'].remove(task)
    save_data(saved_data)


def kill_process_ssh(conn: Connection, pid: str, os_type: str):
    proc = None
    if os_type == 'Linux':
        proc = conn.run(f'kill -9 {pid}')
    elif os_type == 'MacOS':
        proc = conn.run(f'kill -9 {pid}')
    elif os_type == 'Windows':
        proc = conn.run(f'taskkill /pid {pid} /f')
    else:
        raise ValueError('Unknown OS type')
    if proc.return_code:
        if proc.stderr.strip():
            raise ValueError(f'Error killing process: {proc.stderr.strip()}')
        elif proc.stdout.strip():
            raise ValueError(f'Error killing process: {proc.stdout.strip()}')
        else:
            raise ValueError('Error killing process')
    return


def kill_process_paexec(remote_ip, username, password, pid):
    # Команда для остановки процесса на удалённой машине
    kill_command = f"taskkill /PID {pid} /F"

    paexec_command = [
        'paexec.exe', '\\\\' + remote_ip,
        # '-u', username,
        # '-p', password,
        '-i',
        *kill_command.split()
    ]
    process = subprocess.run(paexec_command, capture_output=True)
    if process.returncode == 0:
        print(f"Process PID {pid} stopped successfully")
        return True
    elif process.returncode == 128:
        raise ValueError(f"Error stopping process PID {pid}: process not found")
    else:
        raise ValueError(f"Error stopping process PID {pid}: {process.stderr}")


def shutdown(ip, saved_data, reboot=False):
    """
    Shutdowns a remote device.

    Parameters
    ----------
    ip : str
        IP address of the device.
    saved_data : dict
        Saved data of all devices.
    reboot : bool
        Whether to reboot or shutdown the device.

    Raises
    ------
    ValueError
        If the device is not configured, or there is an error shutting down
        the device.

    """
    username = saved_data['ips'][ip]['username']
    password = saved_data['ips'][ip]['password']
    ssh_key = saved_data['ips'][ip]['ssh_key']
    ssh_use_key = saved_data['ips'][ip]['ssh_use_key']
    ssh_port = saved_data['ips'][ip]['ssh_port']
    os_type = saved_data['ips'][ip]['os_type']
    connect_type = saved_data['ips'][ip]['connect_type']

    if not username or not password and not ssh_key:
        raise ValueError('Configure device')
    if connect_type == 'ssh':
        print('is ssh')
        # try:
        with get_connection(ip, username,
                            password=password,
                            ssh_key=ssh_key,
                            port=ssh_port,
                            ssh_use_key=ssh_use_key) as conn:
            if not os_type:
                os_type, device_name = get_remote_os_and_device_name(conn)
                saved_data['ips'][ip]['os_type'] = os_type
                saved_data['ips'][ip]['device_name'] = device_name
                save_data(saved_data)
            if os_type == 'Windows':
                print('is windows')
                if reboot:
                    shutdown_command = 'shutdown /r /t 5'
                else:
                    shutdown_command = 'shutdown /s /t 5'
                proc = conn.run(shutdown_command, warn=True, hide=True, encoding='cp866')
                print(proc)
                if proc.return_code:
                    if proc.return_code == 5:
                        raise ValueError(f'Error shutting down: User has to be admin')
                    if proc.stdout.strip():
                        raise ValueError(f'Error shutting down: {proc.stdout.strip()}')
                    if proc.stderr.strip():
                        raise ValueError(f'Error shutting down: {proc.stderr.strip()}')
                    raise ValueError('Error shutting down')
            elif os_type == 'Linux':
                print(conn.run('shutdown', hide=True, warn=True))
            elif os_type == 'MacOS':
                print(conn.run('shutdown', hide=True, warn=True))
    elif connect_type == 'paexec':
        shutdown_paexec(ip, username='Honor', password='1234', reboot=reboot)
    



def shutdown_paexec(remote_ip, username='', password='', reboot=False):
    file_name = get_tempfile()
    # Команда для запуска процесса на удалённой машине
    paexec_command = [
        'paexec.exe', '\\\\' + remote_ip
    ]
    if username:
        paexec_command += ['-u', username]
        if password:
            paexec_command += ['-p', password]
    paexec_command += [
        '-lo', 'shutdown.txt',  # -lo сохраняет стандартный вывод в файл
        'shutdown', '-t', '5', '-f'
    ]
    if reboot:
        paexec_command += ['-r']
    process = subprocess.run(paexec_command, stdout=subprocess.PIPE)
    print(process.returncode)