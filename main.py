import nmap
import paramiko
import threading
from json import loads
from time import sleep
from datetime import datetime
from urllib.request import urlopen

import dearpygui.dearpygui as dpg

# user configuration file
import config

ssh_rpi = paramiko.SSHClient()
ssh_rpi.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_rpi_port = config.ssh_rpi_port
ssh_rpi_user = config.ssh_rpi_user
ssh_rpi_pwd = config.ssh_rpi_pwd

ssh_behemoth = paramiko.SSHClient()
ssh_behemoth.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_behemoth_port = config.ssh_behemoth_port
ssh_behemoth_user = config.ssh_behemoth_user
ssh_behemoth_pwd = config.ssh_behemoth_pwd

global ssh_rpi_connected, ssh_behemoth_connected
ssh_rpi_connected = False
ssh_behemoth_connected = False
ssh_usage_cpu = "echo \"\"$[100-$(vmstat 1 2 | tail -1 | awk '{print $15}')]\"\""
ssh_usage_ram = "free -m | head -2 | tail -1 | awk '{print $2,$3,$4}'"
ssh_usage_uptime = "uptime -p"

duinocoin_username = config.duinocoin_username

zt_stalker_feature = config.zt_stalker_feature

if zt_stalker_feature:
    ssh_view_zt_log = "cat /home/pi/scripts/tpo_webhook/zt_stalker_log.txt"

global ssh_rpi_feature, ssh_behemoth_feature
ssh_rpi_feature = False
ssh_behemoth_feature = False

global rpi_status_suffix, behemoth_status_suffix
rpi_status_suffix = ""
behemoth_status_suffix = ""

nm = nmap.PortScanner()
devices = {"192.168.1.1": "Access Point,ap",
           "192.168.1.130": "Raspberry Pi Zero,rpi",
           "192.168.1.109": "Behemoth,behemoth",
           "192.168.1.162": "ESP8266 @ 0,esp0",
           "192.168.1.163": "ESP8266 @ 1,esp1"}

dpg.create_context()
# dpg.create_viewport(title="HOME SERVER DASHBOARD", width=646, height=841, resizable=False, clear_color=(30, 30, 30))
dpg.create_viewport(title="HOME SERVER DASHBOARD", width=646, height=659, resizable=False, clear_color=(30, 30, 30))

ap_status = "offline"
rpi_status = "offline"
behemoth_status = "offline"
esp0_status = "offline"
esp1_status = "offline"

color_red = [211, 47, 47]
color_green = [0, 230, 118]

def background_scanner():
    global rpi_status_suffix
    global behemoth_status_suffix

    global ssh_rpi_feature
    global ssh_behemoth_feature

    while True:
        for k, v in devices.items():
            device_codename = v.split(",")[1]

            # increased timeout for ESPs
            if device_codename.startswith("esp"):
                nm.scan(hosts=k, arguments="-sn -T2")
            else:
                nm.scan(hosts=k, arguments="-sn -T3")

            try:
                status = "online" if nm[k].state() == "up" else "offline"
            except:
                status = "offline"
                if device_codename == "rpi":
                    rpi_status_suffix = ""
                elif device_codename == "behemoth":
                    behemoth_status_suffix = ""
                

            color = color_green if status == "online" else color_red

            tag = f"{v.split(',')[1]}_status_text"

            dpg.delete_item(tag)
            if device_codename == "rpi" and not rpi_status_suffix == "":
                dpg.add_text(label=f"status", default_value=f"{status}{rpi_status_suffix}", color=color, tag=tag, parent=v.split(',')[1])
            elif device_codename == "behemoth" and not behemoth_status_suffix == "":
                dpg.add_text(label=f"status", default_value=f"{status}{behemoth_status_suffix}", color=color, tag=tag, parent=v.split(',')[1])
            else:
                dpg.add_text(label=f"status", default_value=f"{status}", color=color, tag=tag, parent=v.split(',')[1])

            # reset if offline
            if status == "offline":
                if device_codename == "rpi":
                    dpg.set_value(item="rpi_cpu_usage", value=f"CPU Usage: 0%")
                    dpg.set_value(item="rpi_ram_total", value=f"0 MB")
                    dpg.set_value(item="rpi_ram_used", value=f"0 MB")
                    dpg.set_value(item="rpi_ram_free", value=f"0 MB")
                elif device_codename == "behemoth":
                    dpg.set_value(item="behemoth_cpu_usage", value=f"CPU Usage: 0%")
                    dpg.set_value(item="behemoth_ram_total", value=f"0 MB")
                    dpg.set_value(item="behemoth_ram_used", value=f"0 MB")
                    dpg.set_value(item="behemoth_ram_free", value=f"0 MB")
            
            # enable or disable ssh feature if device is offline
            ssh_rpi_feature = True if status == "online" and device_codename == "rpi" else False
            ssh_behemoth_feature = True if status == "online" and device_codename == "behemoth" else False

        sleep(5)


def ssh_connect(host):
    global ssh_rpi_connected
    global ssh_behemoth_connected

    if host == "rpi":
        if not ssh_rpi_connected:
            try:
                ssh_rpi.connect("192.168.1.130", port=ssh_rpi_port, username=ssh_rpi_user, password=ssh_rpi_pwd)
                ssh_rpi_connected = True
            except:
                ssh_rpi_connected = False
                pass

    elif host == "behemoth":
        if not ssh_behemoth_connected:
            try:
                ssh_behemoth.connect("192.168.1.109", port=ssh_behemoth_port, username=ssh_behemoth_user, password=ssh_behemoth_pwd)
                ssh_behemoth_connected = True
            except:
                ssh_behemoth_connected = False
                pass


def ssh_command_manager():
    global ssh_rpi_connected
    global ssh_behemoth_connected

    global ssh_rpi_feature
    global ssh_behemoth_feature

    global rpi_status_suffix
    global behemoth_status_suffix

    zt_iterator = 0

    while True:
        # rpi usage
        if ssh_rpi_feature:
            try:
                if not ssh_rpi_connected:
                    ssh_connect("rpi")

                # cpu
                _, stdout_cpu, _ = ssh_rpi.exec_command(ssh_usage_cpu)
                cpu_usage = stdout_cpu.readlines()[0].strip()
                dpg.set_value(item="rpi_cpu_usage", value=f"CPU Usage: {cpu_usage}%")

                # ram
                _, stdout_ram, _ = ssh_rpi.exec_command(ssh_usage_ram)
                ram_usage = stdout_ram.readlines()[0].strip()
                ram_total, ram_used, ram_free = ram_usage.split(" ")
                dpg.set_value(item="rpi_ram_total", value=f"{ram_total} MB")
                dpg.set_value(item="rpi_ram_used", value=f"{ram_used} MB")
                dpg.set_value(item="rpi_ram_free", value=f"{ram_free} MB")

                # uptime
                _, stdout_uptime, _ = ssh_rpi.exec_command(ssh_usage_uptime)
                uptime = stdout_uptime.readlines()[0].strip()
                rpi_status_suffix = f" ({uptime})"

                ssh_rpi.close()
            except:
                pass

            ssh_rpi_connected = False
        sleep(1)

        # behemoth usage
        if ssh_behemoth_feature:
            try:
                if not ssh_behemoth_connected:
                    ssh_connect("behemoth")

                # cpu
                _, stdout_cpu, _ = ssh_behemoth.exec_command(ssh_usage_cpu)
                cpu_usage = stdout_cpu.readlines()[0].strip()
                dpg.set_value(item="behemoth_cpu_usage", value=f"CPU Usage: {cpu_usage}%")

                # ram
                _, stdout_ram, _ = ssh_behemoth.exec_command(ssh_usage_ram)
                ram_usage = stdout_ram.readlines()[0].strip()
                ram_total, ram_used, ram_free = ram_usage.split(" ")
                dpg.set_value(item="behemoth_ram_total", value=f"{ram_total} MB")
                dpg.set_value(item="behemoth_ram_used", value=f"{ram_used} MB")
                dpg.set_value(item="behemoth_ram_free", value=f"{ram_free} MB")

                # uptime
                _, stdout_uptime, _ = ssh_behemoth.exec_command(ssh_usage_uptime)
                uptime = stdout_uptime.readlines()[0].strip()
                behemoth_status_suffix = f" ({uptime})"

                ssh_behemoth.close()
            except:
                pass
            
            ssh_behemoth_connected = False
        sleep(1)

        # zt stalker
        if zt_stalker_feature and ssh_rpi_feature:
            if zt_iterator <= 0:
                try:
                    if not ssh_rpi_connected:
                        ssh_connect("rpi")

                    _, stdout_zt, _ = ssh_rpi.exec_command(ssh_view_zt_log)
                    zt_log = stdout_zt.readlines()[0].strip()
                    users, last_update = zt_log.split(",")
                    last_update_raw = last_update.split(": ")[1]

                    dpg.set_value(item="zt_status_users", value=f"Users: {users}")
                    dpg.set_value(item="zt_status_last_update", value=last_update)

                    dpg.delete_item(item="zt_status_running")
                    if datetime.now().timestamp() - datetime.strptime(last_update_raw, "%Y-%m-%d %H:%M:%S").timestamp() <= 180:
                        dpg.add_text("running", color=color_green, tag="zt_status_running", parent="zt_stalker_bot")
                    else:
                        dpg.add_text("not running", color=color_red, tag="zt_status_running", parent="zt_stalker_bot")

                    # ssh_rpi.close()
                except:
                    pass

                # ssh_rpi_connected = False
                zt_iterator = 3
                sleep(1)
            else:
                zt_iterator -= 1


def duino_coin_mining_status():
    while True:
        contents_miners = loads(urlopen(f"https://server.duinocoin.com/miners/{duinocoin_username}").read())
        contents_users = loads(urlopen(f"https://server.duinocoin.com/users/{duinocoin_username}").read())
        
        rows = []
        for i in range(len(contents_miners["result"])):
            length = len(str(contents_miners["result"][i]["hashrate"]).split(".")[0])

            if length > 9:
                div, unit = 1000000000, "GH/s"
            elif length > 6:
                div, unit = 1000000, "MH/s"
            elif length > 3:
                div, unit = 1000, "kH/s"
            else:
                div, unit = 1, "H/s"

            identifier = f'{contents_miners["result"][i]["identifier"]}'
            pool = f'{contents_miners["result"][i]["pool"]}'
            diff = f'{contents_miners["result"][i]["diff"]}'
            hashrate = f'{round(contents_miners["result"][i]["hashrate"] / div, 2)} {unit}'
            accuracy = f'{round(contents_miners["result"][i]["accepted"] / (contents_miners["result"][i]["accepted"] + contents_miners["result"][i]["rejected"]) * 100, 1)}%'

            add = True
            for rows_num in range(len(rows)):
                if identifier in rows[rows_num]:
                    add = False
                    break
            
            if add:
                rows.append([identifier, pool, diff, hashrate, accuracy])

        rows.sort()

        dpg.delete_item(item="duinocoin_table")
        with dpg.table(header_row=True, tag="duinocoin_table", parent="duinocoin"):
            dpg.add_table_column(label="Miner")
            dpg.add_table_column(label="Pool")
            dpg.add_table_column(label="Diff")
            dpg.add_table_column(label="Hashrate")
            dpg.add_table_column(label="Accuracy")
            
            for i in range(len(rows)):
                with dpg.table_row():
                    for j in rows[i]:
                        dpg.add_text(j)

        if contents_users["result"]["balance"]["verified"] == "yes":
            verified = "verified"
            verification_color = color_green
        else:
            verified = "not verified"
            verification_color = color_red

        dpg.delete_item("duinocoin_verified")
        dpg.add_text(label="verification", default_value=verified, color=verification_color, tag="duinocoin_verified", parent="duinocoin")

        sleep(10)


# devices
posx, posy = 10, 10
for device in devices.items():
    name = device[1].split(",")[0]
    ip_address = device[0]

    tag = device[1].split(",")[1] # rpi / ap etc.
    tag_ip_address = f"{tag}_ip_address"
    tag_status = eval(f"{tag}_status")
    tag_status_text = f"{tag}_status_text"

    if tag == "ap": pos=(10, 10)
    if tag == "rpi": pos=(10, 120)
    if tag == "behemoth": pos=(320, 10)
    if tag == "esp0": pos=(320, 218)
    if tag == "esp1": pos=(10, 328)

    with dpg.window(label=name, width=300, pos=pos, tag=tag, no_resize=True, no_close=True, no_move=True, no_collapse=True):
        dpg.add_text("Informations")
        dpg.add_input_text(label="IP Address", tag=tag_ip_address, default_value=ip_address, readonly=True)

        if tag == "rpi":
            dpg.add_spacer()
            dpg.add_text("RAM Usage")
            with dpg.table(header_row=True):
                dpg.add_table_column(label="Total")
                dpg.add_table_column(label="Used")
                dpg.add_table_column(label="Free")

                with dpg.table_row():
                    dpg.add_text("0 MB", tag="rpi_ram_total")
                    dpg.add_text("0 MB", tag="rpi_ram_used")
                    dpg.add_text("0 MB", tag="rpi_ram_free")

            dpg.add_spacer()
            dpg.add_text("CPU Usage: 0%", tag="rpi_cpu_usage")
        elif tag == "behemoth":
            dpg.add_spacer()
            dpg.add_text("RAM Usage")
            with dpg.table(header_row=True):
                dpg.add_table_column(label="Total")
                dpg.add_table_column(label="Used")
                dpg.add_table_column(label="Free")

                with dpg.table_row():
                    dpg.add_text("0 MB", tag="behemoth_ram_total")
                    dpg.add_text("0 MB", tag="behemoth_ram_used")
                    dpg.add_text("0 MB", tag="behemoth_ram_free")

            dpg.add_spacer()
            dpg.add_text("CPU Usage: 0%", tag="behemoth_cpu_usage")

        dpg.add_text(label="status", default_value=tag_status, color=color_red, tag=tag_status_text)


# zt stalker
if zt_stalker_feature:
    with dpg.window(label="ZT Stalker Bot", width=300, pos=(320, 328), height=50, tag="zt_stalker_bot", no_resize=True, no_close=True, no_move=True, no_collapse=True):
        dpg.add_text("Users: 0", tag="zt_status_users")
        dpg.add_text("Last update: unknown", tag="zt_status_last_update")
        dpg.add_text("not running", color=color_red, tag="zt_status_running")


# duino coin
with dpg.window(label="Duino-Coin Mining Status", width=610, height=171, pos=(10, 439), tag="duinocoin", no_resize=True, no_close=True, no_move=True, no_collapse=True):
    dpg.add_text(f"Account: {duinocoin_username}")
    dpg.add_spacer()
    with dpg.table(header_row=True, tag="duinocoin_table"):
        dpg.add_table_column(label="Miner")
        dpg.add_table_column(label="Pool")
        dpg.add_table_column(label="Diff")
        dpg.add_table_column(label="Hashrate")
        dpg.add_table_column(label="Accuracy")


# omegle bot
# with dpg.window(label="Omegle Bot", width=610, height=171, pos=(10, 620), tag="omeglebot", no_resize=True, no_close=True, no_move=True, no_collapse=True):
#     with dpg.table(header_row=False, tag="omeglebot_table"):
#         dpg.add_table_column(label="text")


t_background_scanner = threading.Thread(target=background_scanner)
t_background_scanner.daemon = True
t_background_scanner.start()

t_ssh_command_manager = threading.Thread(target=ssh_command_manager)
t_ssh_command_manager.daemon = True
t_ssh_command_manager.start()

t_duinocoin = threading.Thread(target=duino_coin_mining_status)
t_duinocoin.daemon = True
t_duinocoin.start()

dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()