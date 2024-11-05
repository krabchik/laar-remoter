import re
import yaml


def get_data_dict():
    data = None
    try:
        with open('data.yaml', 'r') as file:
            data = yaml.safe_load(file)
    except Exception as e:
        pass
    if not data:
        data = {
            'ips': dict(),
            'tasks': list()
        }
        with open('data.yaml', 'w') as file:
            yaml.dump(data, file)
    return data


def save_data(data):
    with open('data.yaml', 'w') as file:
        yaml.dump(data, file)


def is_ip_valid(ip: str) -> bool:
    ip_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    if not re.match(ip_pattern, ip):
        return False
    if ip.strip() in ['localhost', '127.0.0.1']:
        return False
    return True


def get_default_ip_config():
    default = {
        'connect_type': 'ssh',
        'username': None,
        'password': None,
        'os_type': None,
        'device_name': None,
        'is_online': None,
        'ssh_port': 22,
        'ssh_use_key': False,
        'ssh_key': None,
        'mac': None
    }
    return default


def add_ip(ip: str, dd: dict):
    if not is_ip_valid(ip):
        return None
    if not dd['ips']:
        dd['ips'] = dict()
    if ip not in dd['ips']:
        dd['ips'][ip] = get_default_ip_config()
    return dd


def set_name_for_ip(name: str, ip: str, dd: dict):
    if not is_ip_valid(ip):
        return None

    if not dd['ips'] or ip not in dd['ips']:
        dd = add_ip(ip, dd)
    dd['ips'][ip]['name'] = name
    return dd


def add_group(group: str, dd: dict):
    if not 'groups' in dd:
        dd['groups'] = dict()
    if group not in dd['groups']:
        dd['groups'][group] = set()
    return dd


def add_ip_to_group(ip: str, group: str, dd: dict):
    if ip not in dd['ips']:
        dd = add_ip(ip, dd)
    dd = add_group(group, dd)
    dd['groups'][group].add(ip)
    return dd
