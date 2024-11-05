from flask import render_template, request, abort, Response, flash, url_for, redirect
from pathlib import Path
import time
import os
import asyncio

from remoter import app
from remoter.forms import IPForm, RunForm, DeviceForm, DeviceFormSet
from data import get_data_dict, add_ip, is_ip_valid, save_data
from execute import is_ip_online, wake_on_lan, \
    kill_process, shutdown, async_is_ip_online, get_connection, start_process, get_mac


@app.route('/', methods=['POST', 'GET'])
async def index():
    errors = []
    context = {}
    saved_data = get_data_dict()
    pc_list = saved_data['ips']
    ip_list = list(pc_list.keys())
    context['pc_list'] = pc_list
    context['errors'] = errors
    context['tasks'] = list(reversed(saved_data['tasks']))
    selected_ips = []
    context['selected_ips'] = selected_ips
    form_run = RunForm()
    form_run.ip_addresses.choices = ip_list

    if request.method == 'POST':
        print(request.form)
        if request.form['form_type'] == 'run_command':
            for field_name in request.form.to_dict():
                if field_name.startswith('ip_'):
                    ip = field_name[3:]
                    if not is_ip_valid(ip):
                        errors.append('Некорректный IP адрес')
                    else:
                        if ip not in ip_list:
                            abort(Response('Указанный IP адрес не сохранен'))
                        selected_ips.append(ip)
            if not selected_ips:
                errors.append('Выберите устройство')
            if errors:
                context['selected_ips'] = selected_ips
                return render_template('index.html', context=context, form_run=form_run)
            print('selected ips:', selected_ips)

            if request.form['btn'] == 'Delete Selected':
                print('deleting ips:', selected_ips)
                for ip in selected_ips:
                    if ip in saved_data['ips']:
                        saved_data['ips'].pop(ip)
                save_data(saved_data)
            elif request.form['btn'] == 'Wake On LAN':
                print('waking', selected_ips)
                for ip in selected_ips:
                    wake_on_lan(ip)
            else:
                online_check_tasks = [async_is_ip_online(ip) for ip in selected_ips]
                online_check_results = await asyncio.gather(*online_check_tasks)
                online_ips = []
                for ip in selected_ips:
                    ip_is_online = online_check_results[selected_ips.index(ip)]
                    if ip_is_online:
                        online_ips.append(ip)
                    else:
                        errors.append(f'{ip} не в сети')

                print('online ips:', online_ips)
                selected_ips = online_ips
                context['selected_ips'] = selected_ips

                if request.form['btn'] == 'Start':
                    if not request.form['command']:
                        errors.append('Укажите команду')
                    else:
                        for ip in selected_ips:
                            if not is_ip_online(ip):
                                continue
                            pid = None
                            command = request.form['command']
                            try:
                                pid = start_process(command, saved_data, ip)
                            except Exception as e:
                                print(e)
                                errors.append(f'{ip}: {e}')
                            else:
                                time_obj = time.localtime()  # получить struct_time
                                time_string = time.strftime('%d.%m.%Y %H:%M:%S', time_obj)
                                saved_data['tasks'].append({'ip': ip, 'command': request.form['command'],
                                                            'pid': pid, 'time': time_string, 'type': 'run'})
                        save_data(saved_data)
                elif request.form['btn'] == 'Shutdown':
                    print('shutting down')
                    for ip in selected_ips:
                        if not is_ip_online(ip):
                            print('not online:', ip)
                            errors.append(f'{ip}: not online')
                            continue
                        try:
                            shutdown(ip, saved_data)
                        except Exception as e:
                            print(e)
                            errors.append(f'{ip}: {e}')
                elif request.form['btn'] == 'Reboot':
                    print('rebooting')
                    for ip in selected_ips:
                        if not is_ip_online(ip):
                            print(f'{ip} not online')
                            errors.append(f'{ip}: not online')
                            continue
                        try:
                            print(shutdown(ip, saved_data, reboot=True))
                        except Exception as e:
                            print(e)
                            errors.append(f'{ip}: {e}')
        elif request.form['form_type'] == 'clear_tasks' and request.form['btn'] == 'Clear':
            saved_data['tasks'] = []
            context['tasks'] = []
            save_data(saved_data)
    context['tasks'] = list(reversed(saved_data['tasks']))

    return render_template('index.html', context=context, form_run=form_run)


@app.route('/api/fetch-online')
async def fetch_online():
    ip_list = request.args.getlist('ips')
    print('fetching ips', ip_list)
    online_check_tasks = [async_is_ip_online(ip) for ip in ip_list]
    online_check_results = await asyncio.gather(*online_check_tasks)
    saved_data = get_data_dict()
    zipped = zip(ip_list, online_check_results)
    for ip, status in zipped:
        saved_data['ips'][ip]['is_online'] = status
    save_data(saved_data)
    new_statuses = dict(zip(ip_list, online_check_results))
    return new_statuses


@app.route('/configure', methods=['GET', 'POST'])
def configure_devices():
    saved_data = get_data_dict()
    form_ip = IPForm(prefix='ip')
    if request.method == 'POST':
        if request.form['form_type'] == 'add_ip':
            if form_ip.validate_on_submit():
                ip = form_ip.ip.data
                if not add_ip(ip, saved_data):
                    form_ip.ip.errors = ['Некорректный IP адрес']
                else:
                    if is_ip_online(ip):
                        mac = get_mac(ip)
                        print('got mac', mac)
                        if mac is not None:
                            saved_data['ips'][ip]['mac'] = mac
                    save_data(saved_data)
            elif form_ip.is_submitted():
                form_ip.ip.errors = ['Некорректный IP адрес']
        elif request.form['form_type'] == 'edit_devices':
            filled_form = DeviceFormSet()
            # Обработка данных формы редактирования устройства
            for device in filled_form.data['devices']:
                ip = device['ip']

                if device['username']:
                    saved_data['ips'][ip]['username'] = device['username']
                if device['password']:
                    saved_data['ips'][ip]['password'] = device['password']
                if saved_data['ips'][ip]['os_type'] == 'Windows' and device['connect_type']:
                    saved_data['ips'][ip]['connect_type'] = device['connect_type']
                if device['device_name']:
                    saved_data['ips'][ip]['device_name'] = device['device_name']
                if saved_data['ips'][ip]['connect_type'] == 'ssh':
                    saved_data['ips'][ip]['ssh_use_key'] = bool(device['ssh_use_key'])
                if device['ssh_port']:
                    saved_data['ips'][ip]['ssh_port'] = device['ssh_port']
                else:
                    saved_data['ips'][ip]['ssh_port'] = 22
                # Сохранение SSH ключа, если загружен
                if device['ssh_key']:
                    saved_data['ips'][ip]['ssh_key'] = device['ssh_key'].filename
                    Path(f"keys/{device['ip']}").mkdir(parents=True, exist_ok=True)
                    print(1)
                    ssh_key_path = os.path.join(os.getcwd(), 'keys', ip, device['ssh_key'].filename)
                    device['ssh_key'].save(ssh_key_path)
                    print(2)
            flash("Device configuration updated successfully.", category='info')
        save_data(saved_data)

    devices = saved_data['ips']
    form_data = devices.copy()
    for ip in devices:
        form_data[ip]['ip'] = ip
    form_data = list(form_data.values())
    form = DeviceFormSet(data={'devices': form_data}, formdata=None)

    return render_template('ips.html', devices=devices, form=form, form_ip=form_ip)
