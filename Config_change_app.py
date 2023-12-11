import os
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.messagebox import askyesno
import paramiko
import re
import logging
import requests
from requests.auth import HTTPBasicAuth
from coreapi import codecs, Client, transports
from coreapi.auth import BasicAuthentication
import socket as sock
from enum import Enum
import time
from datetime import datetime
import secrets
import string


ADMIN_USERNAME = 'g2kadmin'
ADMIN_PASSWORD = 'WhenInDoubt,SayNothingAndMoveOn.1973-2130'

GMS_HOST_NAME = "gms.gemini2k.com"
GMS_HOST_PORT = 2210

AMS_USER_NAME = "admin"
AMS_USER_PASS = "ZagreyPaziNi"
AMS_HOST_NAME = "ams-test.gemini2k.com"
AMS_API_SCHEMA_URL = "https://%s/ams/api/schema/" % AMS_HOST_NAME
AMS_API_GROUPACTIONS_URL = "https://%s/ams/apigroupactions/" % AMS_HOST_NAME
AMS_API_ASSETS_URL = "https://%s/ams/apiassets/" % AMS_HOST_NAME
AMS_API_ASSETACTIONS_URL = "https://%s/ams/apiassetactions/" % AMS_HOST_NAME

AMS_GROUPACTION_NAME_REQUEST_RSSH = 'Request SSH reverse tunnel'

RSSH_WAIT_TIMEOUT_SECONDS = 30




class RsshTunnelStatus(Enum):
    OK = 1
    FAILED = 2
    EXCEPTION = 3

class MultiPageApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title("Multi-Page App")
        self.geometry("600x700")
        self.pages = []
        self.page_num = -1

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        pages = (StartPage, ConnectionPage, 
                 ArchiveUploadPage, Cert_Manager_ConfigPage, Settings_T_config_tool, 
                 Settings_M_config_tool, Apn_config, Wpa_supplicant, ChangesLogPage, Generate_New_Password)
        
        self.pages_control = list(pages)
        for F in pages:
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")


        self.button_next = ttk.Button(self, text="Next", command=lambda: self.next_frame())
        self.button_next.pack(side='right')
        

        self.back_button = ttk.Button(self, text="Back", command=lambda: self.back_frame())
        self.back_button.pack(side='left')
        self.back_button.configure(state="disabled")

        
        self.protocol("WM_DELETE_WINDOW", self.confirm)

        self.next_frame()

    def confirm(self):
        ans = askyesno(title='Exit', message='Do you really want to exit?')
        if ans:
            self.destroy()
            self.delete_files()

    
        
    # def show_frame(self, page):
    #     frame = self.frames[page]
    #     frame.tkraise()
    def delete_files(self):
        files_to_delete = ['config_changes_cert.log', 'config_changes_T.log',
                'config_changes_M.log', 'config_changes_apn.log', 'config_changes_wpa.log',
                'cert_manager.conf', 'settings_T.py', 'settings_M.py', 'apn.cfg',
                'wpa_supplicant-wlan0.conf']
        logging.shutdown()
        for i in files_to_delete:
            try:
                os.remove(i)
            except FileNotFoundError:
                continue
            print(f"Deleted {i}")
        
    # def diable_back_button(self):
    #     self.back_button.configure(state='disabled')

    def next_frame(self):
        self.page_num += 1
        try:
            frame = self.frames[self.pages_control[self.page_num]]
            self.back_button.configure(state='diasbled')
            frame.tkraise()
        except IndexError:
            pass
        

    def back_frame(self):
        
        if self.page_num == 0:
            pass
        else:
            self.page_num -= 1
            frame = self.frames[self.pages_control[self.page_num]]
            frame.tkraise()

class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        # controller.diable_back_button()
        label = ttk.Label(self, text="Terminal Configuration Tool", font=("Arial", 20))
        label.pack(pady=100)      

class ConnectionPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        
        ip_label = ttk.Label(self, text="Enter IP/ID:")
        ip_label.pack()
        ip_entry = ttk.Entry(self)
        ip_entry.pack()
            
        connect_button = ttk.Button(self, text="Connect", command=lambda: self.connect_ssh(controller, ip_entry.get()))
        connect_button.pack()
         
    def connect_ssh(self, controller, input_data):
        
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        

        print("Connecting...")

        def is_hexadecimal(s):
            for char in s:
                if not char.isalnum(): 
                    return False
            return True
        
        if not input_data:
            self.incorect_lable = ttk.Label(self, text="No info!")
            self.incorect_lable.pack(pady=30)
            self.update()
        
        elif re.search(regex, input_data):
            self.loading_label = ttk.Label(self, text="Connecting...")
            self.loading_label.pack(pady=30)
            self.update()
            port = 22
            host = input_data
            ssh_client = paramiko.SSHClient()
            print("logging...")

            try:
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(host, port, ADMIN_USERNAME, ADMIN_PASSWORD)
                controller.frames[ArchiveUploadPage].set_ssh_connection(ssh_client)
                # controller.show_frame(ArchiveUploadPage)
                controller.next_frame()
                print("Connected!")

            except Exception as e:
                print("Connection error:", e)

        # check for terminal ID
        elif is_hexadecimal(input_data):
            def __make_http_get_results(url: str, username: str, password: str) -> list:
                next = url
                results = []

                while next is not None:
                    response = requests.get(next, auth=HTTPBasicAuth(username, password))
                    if not response.ok:
                        break

                    resp_dict = response.json()
                    if resp_dict is None:
                        print("Empty json result received for %s" % next)
                        break

                    results_dict = resp_dict.get('results', None)
                    if results_dict is not None:
                        for r in results_dict:
                            results.append(r)
                    # this will return None if either 'links' or 'next' key does not exist.
                    next = resp_dict.get('links', {}).get('next')

                return results
            
            def __make_http_post_request(url: str, username: str, password: str, data: dict) -> dict:
                headers = {'Content-type': 'application/json'}
                response = requests.post(url, json=data, headers=headers,
                                            auth=HTTPBasicAuth(username, password))
                if not response.ok:
                    return {}
                return response.json()
            
            def __make_http_delete_request(url: str, username: str, password: str) -> bool:
                headers = {'Content-type': 'application/json'}
                response = requests.delete(url, headers=headers,
                                            auth=HTTPBasicAuth(username, password))
                return response.ok
            
            # //syzdavane na zapis v BD za izpylnqvane na AMS Reverse SSH request. Ideqta e da ima record, koito da opisva che iskame da otvorim tunel za opredelen terminal. 
            # //Tozi record se polzwa za izpylnqwane na zadacha v bek ofisa.
            def create_ams_rssh_action(terminal_id: str) -> int:
                # // izvlichane na terminalite ot AMS BD s get parameter opredelen terminal posochen s 'serial_number' i variable terminal_id, koeto e tvoeto vyvedno v apa ti FCC23D*******
                ams_assets = __make_http_get_results('%s?serial_number=%s' % (AMS_API_ASSETS_URL, terminal_id), AMS_USER_NAME, AMS_USER_PASS)
                if len(ams_assets) <= 0:
                    print("No terminal found with SN=%s. Waiting for gms_reverse_ssh.sh to start the tunnel.\n" % terminal_id)
                    return -1
                
                # // vryshtame record ID na terminala podaden kato parameter terminal_id FCC23D*******
                terminal_id = ams_assets[0]['id']

                # // izvlichane na AMS group action-ite. Tuk sa definirani kakvi zadachi mogat da se izpylnqvat za opredelen terminal. V sluchaq nashata zadacha e da izpylnim zadacha za aktivirane na RSSH tunnel
                ams_group_actions = __make_http_get_results(AMS_API_GROUPACTIONS_URL, AMS_USER_NAME, AMS_USER_PASS)
                if len(ams_group_actions) <= 0:
                    print("No group actions found!\n")
                    return -1

                # // vzemame id-to na zadachata ot tip REVERSE SSH 
                group_action_id = -1
                for ga in ams_group_actions:
                    if ga['name'] == AMS_GROUPACTION_NAME_REQUEST_RSSH:
                        group_action_id = ga['id']
                        break

                if group_action_id == -1:
                    print("No RSSH group action found!\n")
                    return -1

                # //syzdavame json mesidja za zapisvane na zadachata v BD. ID-to na tozi record shte se izpolzva za izpylnqvane na syzdadenata zadacha
                data = {
                    #'id': 459,
                    'group_action': group_action_id,
                    #'status': 'PENDING',
                    'asset': terminal_id
                }

                # create record in DB
                resp_dict = __make_http_post_request(AMS_API_ASSETACTIONS_URL, AMS_USER_NAME, AMS_USER_PASS, data)
                if len(resp_dict) <= 0:
                    print("Empty json result received for %s\n" % AMS_API_ASSETACTIONS_URL)
                    return -1
                        
                return resp_dict['id']

            def delete_ams_rssh_action(id: int) -> bool:
                return __make_http_delete_request('%s%d/' % (AMS_API_ASSETACTIONS_URL, id), AMS_USER_NAME, AMS_USER_PASS)
            
            def force_rssh(ams_rssh_action_id) -> bool:
                try: 
                    auth = BasicAuthentication(
                        username=AMS_USER_NAME,
                        password=AMS_USER_PASS
                    )
                    session = requests.Session()
                    session.verify = True
                    tr = transports.HTTPTransport(
                        auth=auth, session=session)

                    client = Client(transports=[tr], decoders=[
                                    codecs.CoreJSONCodec(), codecs.JSONCodec()])

                    schema = client.get(
                        AMS_API_SCHEMA_URL, format='corejson', )
                    #print(schema)

                    action = ['apitasks', 'execute_sshrt_actions']
                    params={
                        'actions': str(ams_rssh_action_id),
                    }

                    # EXAMPLE !!!
                    #action = ['apiassets', 'list']
                    #params={
                    #    'page': 1,
                    #    'page_size': 500,
                    #}

                    res_dict = client.action(schema, action, params=params, validate=False)
                    
                    # //TODO: How we know that the action is executed successfully or not ??? This method action() returnes always empty OrderDict()
                            
                    session.close()
                except Exception as e:
                    print(e)
                    return False

                return True
            
            def is_rssh_tunnel_opened() -> int:
                create_socket = None
                destination = (GMS_HOST_NAME, GMS_HOST_PORT)
                result = 0

                try: 
                    create_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                except sock.error as e: 
                    print("Error creating socket: %s" % e) 
                    return RsshTunnelStatus.EXCEPTION
                
                try:
                    result = create_socket.connect_ex(destination)
                except sock.error as exc:
                    print("Error connecting socket: %s" % exc)
                    return RsshTunnelStatus.EXCEPTION
                
                try:
                    create_socket.close()
                except sock.error as exc:
                    print("Error closing socket: %s" % exc)
                    return RsshTunnelStatus.EXCEPTION
                
                return RsshTunnelStatus.OK if result == 0 else RsshTunnelStatus.FAILED
            
            ams_action_rssh_id = -1
            if is_rssh_tunnel_opened() == RsshTunnelStatus.OK:
                print('Tunnel already opened. No need of AMS RSSH action.')
            else:
                ams_action_rssh_id = create_ams_rssh_action(input_data)
                if ams_action_rssh_id != -1:
                    print('Created RSSH AMS action record with id=%d\n' % ams_action_rssh_id)
                    r = force_rssh(ams_action_rssh_id)
                    if r == True:
                        print('RSSH tunnel for terminal %s requested at %s' % (input_data, datetime.today().strftime('%Y-%m-%d %H:%M:%S')))
                        print('AMS RSSH action successfully executed for the terminal %s\n' % input_data)
                        
            start_time = time.time()
            is_connection_established = False
            while True:
                if is_rssh_tunnel_opened() == RsshTunnelStatus.OK:
                    print('SUCCESS: RSSH tunnel opened at %s (Took: %s seconds)' % (datetime.today().strftime('%Y-%m-%d %H:%M:%S'), round(time.time() - start_time)))
                    is_connection_established = True
                    break
                    
                time.sleep(5)
                if (time.time() - start_time) >= RSSH_WAIT_TIMEOUT_SECONDS:
                    print('FAILED: Timeout reached - no RSSH tunnel opened within defined timeframe\n')
                    break
                    
            # delete ams_action_rssh record in AMS
            if ams_action_rssh_id != -1:
                res = delete_ams_rssh_action(ams_action_rssh_id)
                if res == True:
                    print('Deleted AMS RSSH action record with id=%d\n' % ams_action_rssh_id)
                    
            if is_connection_established:
                self.loading_label = ttk.Label(self, text="Connecting...")
                self.loading_label.pack(pady=30)
                self.update()
                ssh_client = paramiko.SSHClient()
                print("logging...")

                try:
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(GMS_HOST_NAME, GMS_HOST_PORT, ADMIN_USERNAME, ADMIN_PASSWORD)
                    controller.frames[ArchiveUploadPage].set_ssh_connection(ssh_client)
                    # controller.show_frame(ArchiveUploadPage)
                    controller.next_frame()
                    print("Connected!")

                except Exception as e:
                    print("Connection error:", e)
        
        
        else:
            self.incorect_lable = ttk.Label(self, text="IP/ID is incorect!")
            self.incorect_lable.pack(pady=30)
            self.update()

class ArchiveUploadPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.ssh_client = None
        
        self.label_text = ttk.Label(self, text='Connected Successfully!')
        self.upload_button = ttk.Button(self, text="Upload file", command=self.upload_action)
        self.label_text.pack(pady=30)
        self.upload_button.pack(pady=30)

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client 

    def upload_action(self):
        self.loading_label = ttk.Label(self, text="Getting data...")
        self.loading_label.pack(pady=30)

        filename = filedialog.askopenfilename()
        selected_label = ttk.Label(self, text="File selected!")
        selected_label.pack(pady=10)

        print("connecting sftp")
        ftp_client = self.ssh_client.open_sftp()
        
        print("putting file")
        ftp_client.put(filename, '/home/g2k/.g2k_patch/production.zip')
        
        commands = ['rm -rf /home/g2k/.g2k_patch/production', 'unzip /home/g2k/.g2k_patch/production.zip -d /home/g2k/.g2k_patch/']
        for command in commands:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print(f"Command '{command}' executed successfully")
            else:
                print(f"Command '{command}' failed with exit status {exit_status}")
        
        self.controller.frames[Cert_Manager_ConfigPage].set_ssh_connection(self.ssh_client)
        self.controller.next_frame()

        self.controller.frames[Settings_T_config_tool].set_ssh_connection(self.ssh_client)
        self.controller.frames[Settings_M_config_tool].set_ssh_connection(self.ssh_client)
        self.controller.frames[Apn_config].set_ssh_connection(self.ssh_client)
        self.controller.frames[Wpa_supplicant].set_ssh_connection(self.ssh_client)
        self.controller.frames[ChangesLogPage].set_ssh_connection(self.ssh_client)
        self.controller.frames[Generate_New_Password].set_ssh_connection(self.ssh_client)

class Cert_Manager_ConfigPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.ssh_client = None

        self.data_cert = None

        self.env = []
        self.env_text = None
        self.cert_virtual = '/home/g2k/.g2k_patch/production/G2K_Terminal/cert_manager.conf'
        self.cert_local = 'cert_manager.conf'

        

        self.config_log_filename = 'config_changes_cert.log'
        self.config_changes_logger = self.setup_config_changes_logger()
        open(self.config_log_filename, 'w').close()

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client 
        self.sftp = self.ssh_client.open_sftp()
        self.sftp.get(self.cert_virtual, self.cert_local)
        self.show_data()
        
    def show_data(self):
        with open(self.cert_local, 'r') as cert_file:
            self.data_cert = cert_file.read()
            self.pattern = r'^(api_schema=)([^#\n]+)'
            self.matches = re.findall(self.pattern, self.data_cert, re.MULTILINE)

            if self.matches:
                self.env.append(self.matches[-1][1])
        
        self.label_text = ttk.Label(self, text='Choose environment:')
        self.label_text.pack(pady=30)

        self.production = ttk.Button(self, text="Production", command=self.set_production)
        self.production.pack()

        self.test = ttk.Button(self, text="Test", command=self.set_test)
        self.test.pack()


    def set_production(self):
        self.env.append('https://ams.gemini2k.com/ams/api/schema')
        self.env_text = 'production'
        self.save_env()

    def set_test(self):
        self.env.append('https://ams-test.gemini2k.com/ams/api/schema')
        self.env_text = 'test'
        self.save_env()

    def setup_config_changes_logger(self):
        logger = logging.getLogger("config_changes_cert")
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - cert_manager %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        file_handler = logging.FileHandler(self.config_log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def save_env(self):
        print(self.env)
        if self.env[0] != self.env[-1]:
            last_api_schema = self.matches[-1][0] + self.env[-1]
            self.data_cert = re.sub(self.pattern, last_api_schema, self.data_cert, flags=re.MULTILINE)
            self.config_changes_logger.info(f"Changed 'api_schema' from '{self.env[0]}' to '{self.env[-1]}'")

            with open(self.cert_local, 'w') as cert_file:
                cert_file.write(self.data_cert)

        # Update the environment text in the target page
        print(self.env_text)
        self.controller.frames[Settings_T_config_tool].set_env(self.env_text)
        self.controller.next_frame()

class Settings_T_config_tool(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.ssh_client = None
        self.sftp = None
        self.controller = controller

        self.set_T_data = None

        self.display_model = []
        self.no_bo_connection = []
        self.epos_interface = []
        self.g2k_bo_server_address_env = []
        self.epos_internal_link = []
        self.reader_port_name = []
        self.ing_epos_server_address = []
        self.ing_bo_server_port = []
        self.g2k_bo_hb_internal = []
        self.g2k_bo_server_port = []
        self.psp_name = []

        self.dropdown_options = {
            'DISPLAY_MODEL': ['SSD1305_OLED_128x32', 'ST7789V_LCD_240x320'],
            'NO_BO_CONNECTION': [True, False],
            'EPOS_INTERFACE': ['G2K', 'Ingenico'],
            'EPOS_INTERNAL_LINK': [True, False],
            'READER_PORT_NAME': ['/dev/ttyS1', '/dev/ttyS2'],
            # Add more dropdown options as needed
        }

        self.settings_t_terminal ='/home/g2k/.g2k_patch/production/G2K_Terminal/settings_T.py'
        self.settings_t_local = 'settings_T.py'

        self.config_log_filename = 'config_changes_T.log'
        self.config_changes_logger = self.setup_config_changes_logger()
        open(self.config_log_filename, 'w').close()


        self.label_text = ttk.Label(self, text='Settings_T Config Page')
        self.label_text.pack(pady=30)
        

    def set_env(self, env_text):
        print(env_text)
        if env_text == 'production':
            self.g2k_bo_server_address_env.append('mqtt.gemini2k.com') 
        elif env_text == 'test':
            self.g2k_bo_server_address_env.append('mqtt-test.gemini2k.com')
        self.show_data()
        

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
        self.sftp = self.ssh_client.open_sftp()
        self.sftp.get(self.settings_t_terminal, self.settings_t_local)


    def show_data(self):
        with open(self.settings_t_local, 'r') as set_t_file:
            self.set_T_data = set_t_file.read()

            display_model_match = re.search(r"'DISPLAY_MODEL': '(.*)',", self.set_T_data)
            no_bo_connection_match = re.search(r"'NO_BO_CONNECTION': (.*),", self.set_T_data)
            epos_interface_match = re.search(r"'EPOS_INTERFACE':\s*'([^#']*)',", self.set_T_data)
            g2k_bo_server_address_env_match = re.search(r"'G2K_BO_SERVER_ADDRESS': '(.*)',", self.set_T_data)
            epos_internal_link_match = re.search(r"'EPOS_INTERNAL_LINK': (.*),", self.set_T_data)
            reader_port_name_match = re.search(r"'READER_PORT_NAME': b\'(.*)',", self.set_T_data)
            ing_epos_server_address_match = re.search(r"'ING_EPOS_SERVER_ADDRESS': '(.*)',", self.set_T_data)
            ing_bo_server_port_match = re.search(r"'ING_EPOS_SERVER_PORT': (.*),", self.set_T_data)
            g2k_bo_hb_internal_match = re.search(r"'G2K_BO_HB_INTERVAL': (.*),", self.set_T_data)
            g2k_bo_server_port_match = re.search(r"'G2K_BO_SERVER_PORT': (.*),", self.set_T_data)
            psp_name_match = re.search(r"'PSP_NAME':\s*'(.*)',", self.set_T_data)

            if display_model_match:
                self.display_model.append(display_model_match.group(1).strip())

            if no_bo_connection_match:
                self.no_bo_connection.append(no_bo_connection_match.group(1).strip())
            
            if epos_interface_match:
                self.epos_interface.append(epos_interface_match.group(1).strip())
            
            if g2k_bo_server_address_env_match:
                self.g2k_bo_server_address_env.insert(0, g2k_bo_server_address_env_match.group(1).strip())
            
            if epos_internal_link_match:
                self.epos_internal_link.append(epos_internal_link_match.group(1).strip())
            
            if reader_port_name_match:
                self.reader_port_name.append(reader_port_name_match.group(1).strip())
            
            if ing_epos_server_address_match:
                self.ing_epos_server_address.append(ing_epos_server_address_match.group(1).strip())
            
            if ing_bo_server_port_match:
                self.ing_bo_server_port.append(ing_bo_server_port_match.group(1).strip())
            
            if g2k_bo_hb_internal_match:
                self.g2k_bo_hb_internal.append(g2k_bo_hb_internal_match.group(1).strip())
            
            if g2k_bo_server_port_match:
                self.g2k_bo_server_port.append(g2k_bo_server_port_match.group(1).strip())
            
            if psp_name_match:
                self.psp_name.append(psp_name_match.group(1).strip())

        
        display_model_label = ttk.Label(self, text="DISPLAY_MODEL")
        display_model_label.pack()
        self.display_model_combo = ttk.Combobox(self, values=self.dropdown_options['DISPLAY_MODEL'], state="readonly")
        self.display_model_combo.set(self.display_model[0])  # Set default value if found
        self.display_model_combo.pack()
        

        no_bo_connection_label = ttk.Label(self, text="NO_BO_CONNECTION")
        no_bo_connection_label.pack()
        self.no_bo_connection_combo = ttk.Combobox(self, values=self.dropdown_options['NO_BO_CONNECTION'], state="readonly")
        self.no_bo_connection_combo.set(self.no_bo_connection[0])  # Set default value
        self.no_bo_connection_combo.pack()
        

        epos_interface_label = ttk.Label(self, text="EPOS_INTERFACE")
        epos_interface_label.pack()
        self.epos_interface_combo = ttk.Combobox(self, values=self.dropdown_options['EPOS_INTERFACE'], state="readonly")
        self.epos_interface_combo.set(self.epos_interface[0])  # Set default value
        self.epos_interface_combo.pack()

        g2k_bo_server_address_env_label = ttk.Label(self, text="G2K_BO_SERVER_ADDRESS")
        g2k_bo_server_address_env_label.pack()
        self.g2k_bo_server_address_env_entry = ttk.Entry(self)
        self.g2k_bo_server_address_env_entry.insert(0, self.g2k_bo_server_address_env[1])
        self.g2k_bo_server_address_env_entry.configure(state='readonly')
        self.g2k_bo_server_address_env_entry.pack()

        epos_internal_link_label = ttk.Label(self, text="EPOS_INTERNAL_LINK")
        epos_internal_link_label.pack()
        self.epos_internal_link_combo = ttk.Combobox(self, values=self.dropdown_options['EPOS_INTERNAL_LINK'], state="readonly")
        self.epos_internal_link_combo.set(self.epos_internal_link[0])  # Set default value
        self.epos_internal_link_combo.pack()

        reader_port_name_label = ttk.Label(self, text="READER_PORT_NAME")
        reader_port_name_label.pack()
        self.reader_port_name_combo = ttk.Combobox(self, values=self.dropdown_options['READER_PORT_NAME'], state="readonly")
        self.reader_port_name_combo.set(self.reader_port_name[0])  # Set default value
        self.reader_port_name_combo.pack()
        
        ing_epos_server_address_label = ttk.Label(self, text="ING_EPOS_SERVER_ADDRESS")
        ing_epos_server_address_label.pack()
        self.ing_epos_server_address_entry = ttk.Entry(self)
        self.ing_epos_server_address_entry.insert(0, self.ing_epos_server_address[0])
        self.ing_epos_server_address_entry.pack()

        ing_bo_server_port_label = ttk.Label(self, text="ING_EPOS_SERVER_PORT")
        ing_bo_server_port_label.pack()
        self.ing_bo_server_port_entry = ttk.Entry(self)
        self.ing_bo_server_port_entry.insert(0, self.ing_bo_server_port[0])
        self.ing_bo_server_port_entry.pack()

        g2k_bo_hb_internal_label = ttk.Label(self, text="G2K_BO_HB_INTERVAL")
        g2k_bo_hb_internal_label.pack()
        self.g2k_bo_hb_internal_entry = ttk.Entry(self)
        self.g2k_bo_hb_internal_entry.insert(0, self.g2k_bo_hb_internal[0])
        self.g2k_bo_hb_internal_entry.pack()


        g2k_bo_server_port_label = ttk.Label(self, text="G2K_BO_SERVER_PORT")
        g2k_bo_server_port_label.pack()
        self.g2k_bo_server_port_entry = ttk.Entry(self)
        self.g2k_bo_server_port_entry.insert(0, self.g2k_bo_server_port[0])
        self.g2k_bo_server_port_entry.pack()

        psp_name_label = ttk.Label(self, text="PSP_NAME")
        psp_name_label.pack()
        self.psp_name_entry = ttk.Entry(self)
        self.psp_name_entry.insert(0, self.psp_name[0])
        self.psp_name_entry.pack()


        save_button = ttk.Button(self, text="Save", command=self.save_env)
        save_button.pack(pady=10)

    def setup_config_changes_logger(self):
        logger = logging.getLogger("config_changes_T")
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - settings_T %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        file_handler = logging.FileHandler(self.config_log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger
    

    def save_env(self):
        self.display_model.append(self.display_model_combo.get()) 
        self.no_bo_connection.append(self.no_bo_connection_combo.get())
        self.epos_interface.append(self.epos_interface_combo.get())
        self.g2k_bo_server_address_env.append(self.g2k_bo_server_address_env_entry.get())
        self.epos_internal_link.append(self.epos_internal_link_combo.get())
        self.reader_port_name.append(self.reader_port_name_combo.get())
        self.ing_epos_server_address.append(self.ing_epos_server_address_entry.get())
        self.ing_bo_server_port.append(self.ing_bo_server_port_entry.get())
        self.g2k_bo_hb_internal.append(self.g2k_bo_hb_internal_entry.get())
        self.g2k_bo_server_port.append(self.g2k_bo_server_port_entry.get())
        self.psp_name.append(self.psp_name_entry.get())

        open(self.config_log_filename, 'w').close()
        
        if self.display_model[0] != self.display_model[-1]:
            self.set_T_data = re.sub(r"'DISPLAY_MODEL': '(.*)',", f"'DISPLAY_MODEL': '{self.display_model[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'DISPLAY_MODEL' from '{self.display_model[0]}' to '{self.display_model[-1]}'")
        
        if self.no_bo_connection[0] != self.no_bo_connection[-1]:
            self.set_T_data = re.sub(r"'NO_BO_CONNECTION': (.*),", f"'NO_BO_CONNECTION': {self.no_bo_connection[-1]},", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'NO_BO_CONNECTION' from {self.no_bo_connection[0]} to {self.no_bo_connection[-1]}")
        
        if self.epos_interface[0] != self.epos_interface[-1]:
            self.set_T_data = re.sub(r"'EPOS_INTERFACE':\s*'([^#']*)',", f"'EPOS_INTERFACE': '{self.epos_interface[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'EPOS_INTERFACE' from '{self.epos_interface[0]}' to '{self.epos_interface[-1]}'")
        
        if self.g2k_bo_server_address_env[0] != self.g2k_bo_server_address_env[-1]:
            self.set_T_data = re.sub(r"'G2K_BO_SERVER_ADDRESS': '(.*)',", f"'G2K_BO_SERVER_ADDRESS': '{self.g2k_bo_server_address_env[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'G2K_BO_SERVER_ADDRESS' from '{self.g2k_bo_server_address_env[0]}' to '{self.g2k_bo_server_address_env[-1]}'")
        
        if self.epos_internal_link[0] != self.epos_internal_link[-1]:
            self.set_T_data = re.sub(r"'EPOS_INTERNAL_LINK': (.*),", f"'EPOS_INTERNAL_LINK': {self.epos_internal_link[-1]},", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'EPOS_INTERNAL_LINK' from {self.epos_internal_link[0]} to {self.epos_internal_link[-1]}")
        
        if self.reader_port_name[0] != self.reader_port_name[-1]:
            self.set_T_data = re.sub(r"'READER_PORT_NAME': b\'(.*)',", f"'READER_PORT_NAME': '{self.reader_port_name[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'READER_PORT_NAME' from '{self.reader_port_name[0]}' to '{self.reader_port_name[-1]}'")
        
        if self.ing_epos_server_address[0] != self.ing_epos_server_address[-1]:
            self.set_T_data = re.sub(r"'ING_EPOS_SERVER_ADDRESS': '(.*)',", f"'ING_EPOS_SERVER_ADDRESS': '{self.ing_epos_server_address[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'ING_EPOS_SERVER_ADDRESS' from '{self.ing_epos_server_address[0]}' to '{self.ing_epos_server_address[-1]}'")
        
        if self.ing_bo_server_port[0] != self.ing_bo_server_port[-1]:
            self.set_T_data = re.sub(r"'ING_EPOS_SERVER_PORT': (.*),", f"'ING_EPOS_SERVER_PORT': {self.ing_bo_server_port[-1]},", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'ING_EPOS_SERVER_PORT' from {self.ing_bo_server_port[0]} to {self.ing_bo_server_port[-1]}")
        
        if self.g2k_bo_hb_internal[0] != self.g2k_bo_hb_internal[-1]:
            self.set_T_data = re.sub(r"'G2K_BO_HB_INTERVAL': (.*),", f"'G2K_BO_HB_INTERVAL': {self.g2k_bo_hb_internal[-1]},", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'G2K_BO_HB_INTERVAL' from {self.g2k_bo_hb_internal[0]} to {self.g2k_bo_hb_internal[-1]}")
        
        if self.g2k_bo_server_port[0] != self.g2k_bo_server_port[-1]:
            self.set_T_data = re.sub(r"'G2K_BO_SERVER_PORT': (.*),", f"'G2K_BO_SERVER_PORT': {self.g2k_bo_server_port[-1]},", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'G2K_BO_SERVER_PORT' from {self.g2k_bo_server_port[0]} to {self.g2k_bo_server_port[-1]}")
        
        if self.psp_name[0] != self.psp_name[-1]:
            self.set_T_data = re.sub(r"'PSP_NAME':\s*'(.*)',", f"'PSP_NAME': '{self.psp_name[-1]}',", self.set_T_data)
            self.config_changes_logger.info(f"Changed 'PSP_NAME' from '{self.psp_name[0]}' to '{self.psp_name[-1]}'")
        

        with open(self.settings_t_local, 'w') as set_t_file:
            set_t_file.write(self.set_T_data)

        self.controller.next_frame()

class Settings_M_config_tool(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        self.ssh_client = None
        self.sftp = None
        self.controller = controller

        self.set_M_data = None

        self.customer_reference = []
        self.payment_currency = []

        self.settings_M_terminal ='/home/g2k/.g2k_patch/production/G2K_MDB_Cashless/settings_M.py'
        self.settings_M_local = 'settings_M.py'

        self.config_log_filename = 'config_changes_M.log'
        self.config_changes_logger = self.setup_config_changes_logger()
        open(self.config_log_filename, 'w').close()

        self.label_text = ttk.Label(self, text='Settings_M Config Page')
        self.label_text.pack(pady=30)
        

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
        self.sftp = self.ssh_client.open_sftp()
        self.sftp.get(self.settings_M_terminal, self.settings_M_local)
        self.show_data()


    def show_data(self):
        with open(self.settings_M_local, 'r') as set_m_file:
            self.set_M_data = set_m_file.read()

            customer_refrence_match = re.search(r"'CUSTOMER_REFERENCE': '(.*)',", self.set_M_data)
            payment_currency_match = re.search(r"'PAYMENT_CURRENCY': (.*),", self.set_M_data)

            if customer_refrence_match:
                self.customer_reference.append(customer_refrence_match.group(1).strip())


            if payment_currency_match:
                self.payment_currency.append(payment_currency_match.group(1).strip())
        
        cr_label = ttk.Label(self, text="CUSTOMER_REFERENCE")
        cr_label.pack()

        self.cr_entry = ttk.Entry(self)
        self.cr_entry.insert(0, self.customer_reference[0])
        self.cr_entry.pack()
        
        pc_label = ttk.Label(self, text="PAYMENT_CURRENCY")
        pc_label.pack()

        self.pc_entry = ttk.Entry(self)
        self.pc_entry.insert(0, self.payment_currency[0])
        self.pc_entry.pack()

        save_button = ttk.Button(self, text="Save", command=self.save_env)
        save_button.pack(pady=10)

    def setup_config_changes_logger(self):
        logger = logging.getLogger("config_changes_M")
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - settings_M %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        file_handler = logging.FileHandler(self.config_log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger
    def save_env(self):
        self.customer_reference.append(self.cr_entry.get())
        self.payment_currency.append(self.pc_entry.get())

        open(self.config_log_filename, 'w').close()

        if self.customer_reference[0] != self.customer_reference[-1]:
            self.set_M_data = re.sub(r"'CUSTOMER_REFERENCE': '(.*)',", f"'CUSTOMER_REFERENCE': '{self.customer_reference[-1]}',", self.set_M_data)
            self.config_changes_logger.info(f"Changed 'CUSTOMER_REFERENCE' from '{self.customer_reference[0]}' to '{self.customer_reference[-1]}'")
        
        if self.payment_currency[0] != self.payment_currency[-1]:
            self.set_M_data = re.sub(r"'PAYMENT_CURRENCY': (.*),", f"'PAYMENT_CURRENCY': {self.payment_currency[-1]},", self.set_M_data)
            self.config_changes_logger.info(f"Changed 'PAYMENT_CURRENCY' from {self.payment_currency[0]} to {self.payment_currency[-1]}")
        
        
        with open(self.settings_M_local, 'w') as set_m_file:
            set_m_file.write(self.set_M_data)

        self.controller.next_frame()

class Apn_config(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        
        self.controller = controller
        self.ssh_client = None
        self.sftp = None


        self.apn_data = None

        self.apn_value = []
        self.port_value = []

        self.apn_cfg_terminal = '/opt/4G_modems/apn.cfg'
        self.apn_cfg_local = 'apn.cfg'

        self.label_text = ttk.Label(self, text='Apn.cfg')
        self.label_text.pack(pady=30)

        self.config_log_filename = 'config_changes_apn.log'
        self.config_changes_logger = self.setup_config_changes_logger()
        open(self.config_log_filename, 'w').close()
        

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
        self.sftp = self.ssh_client.open_sftp()
        self.sftp.get(self.apn_cfg_terminal, self.apn_cfg_local)
        self.show_data()



    def show_data(self):
        with open(self.apn_cfg_local, 'r') as apn_file:
            self.apn_data = apn_file.read()
            apn_match = re.search(r'APN:(.*)', self.apn_data)
            port_match = re.search(r'PORT:(.*)', self.apn_data)

            if apn_match:
                self.apn_value.append(apn_match.group(1).strip())

            if port_match:
                self.port_value.append(port_match.group(1).strip())
        
        apn_label = ttk.Label(self, text="APN")
        apn_label.pack()

        self.apn_entry = ttk.Entry(self)
        self.apn_entry.insert(0, self.apn_value[0])
        self.apn_entry.pack()

        port_label = ttk.Label(self, text="PORT")
        port_label.pack()

        self.port_entry = ttk.Entry(self)
        self.port_entry.insert(0, self.port_value[0])
        self.port_entry.pack()

        save_button = ttk.Button(self, text="Save", command=self.save_env)
        save_button.pack(pady=10)

    def setup_config_changes_logger(self):
        logger = logging.getLogger("config_changes_apn")
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - Apn_cfg %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        file_handler = logging.FileHandler(self.config_log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def save_env(self):
        self.apn_value.append(self.apn_entry.get())
        self.port_value.append(self.port_entry.get())

        open(self.config_log_filename, 'w').close()
        
        if self.apn_value[0] != self.apn_value[-1]:
            self.apn_data = re.sub(r'APN:(.*)', f'APN:{self.apn_value[-1]}', self.apn_data)
            self.config_changes_logger.info(f"Changed 'APN' from '{self.apn_value[0]}' to '{self.apn_value[-1]}'")
        
        if self.port_value[0] != self.port_value[-1]:
            self.apn_data = re.sub(r'PORT:(.*)', f'PORT:{self.port_value[-1]}', self.apn_data)
            self.config_changes_logger.info(f"Changed 'PORT' from '{self.port_value[0]}' to '{self.port_value[-1]}'")

        with open('apn.cfg', 'w') as apn_file:
            apn_file.write(self.apn_data)

        self.controller.next_frame()
        
class Wpa_supplicant(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        
        self.controller = controller
        self.ssh_client = None

        self.wpa_data = None
        
        self.ssid = []
        self.psk = []
        self.priority = []

        self.wpa_supplicant_terminal = '/etc/wpa_supplicant/wpa_supplicant-wlan0.conf'
        self.wpa_supplicant_local = 'wpa_supplicant-wlan0.conf'

        self.label_text = ttk.Label(self, text='wpa_supplicant-wlan0.conf')
        self.label_text.pack(pady=30)
        
        self.config_log_filename = 'config_changes_wpa.log'
        self.config_changes_logger = self.setup_config_changes_logger()
        open(self.config_log_filename, 'w').close()
        
        
    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
        self.sftp = self.ssh_client.open_sftp()
        self.sftp.get(self.wpa_supplicant_terminal, self.wpa_supplicant_local)
        self.show_data()



    def show_data(self):
        with open(self.wpa_supplicant_local, 'r') as wpa_file:
            self.wpa_data = wpa_file.read()

            ssid_match = re.search(r'ssid="(.*)"', self.wpa_data)
            psk_match = re.search(r'psk="(.*)"', self.wpa_data)
            priority_match = re.search(r'priority=(.*)', self.wpa_data)

            if ssid_match:
                self.ssid.append(ssid_match.group(1).strip())

            if psk_match:
                self.psk.append(psk_match.group(1).strip())

            if priority_match:
                self.priority.append(priority_match.group(1).strip())
        
        ssid_label = ttk.Label(self, text="SSID")
        ssid_label.pack()

        self.ssid_entry = ttk.Entry(self)
        self.ssid_entry.insert(0, self.ssid[0])
        self.ssid_entry.pack()

        psk_label = ttk.Label(self, text="PSK")
        psk_label.pack()

        self.psk_entry = ttk.Entry(self)
        self.psk_entry.insert(0, self.psk[0])
        self.psk_entry.pack()
        
        priority_label = ttk.Label(self, text="Priority")
        priority_label.pack()

        self.priority_entry = ttk.Entry(self)
        self.priority_entry.insert(0, self.priority[0])
        self.priority_entry.pack()

        save_button = ttk.Button(self, text="Save", command=self.save_env)
        save_button.pack(pady=10)

    def setup_config_changes_logger(self):
        logger = logging.getLogger("config_changes_wpa")
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - wpa_supplicant-wlan0_conf %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        file_handler = logging.FileHandler(self.config_log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def save_env(self):
        self.ssid.append(self.ssid_entry.get())
        self.psk.append(self.psk_entry.get())
        self.priority.append(self.priority_entry.get())

        open(self.config_log_filename, 'w').close()

        if self.ssid[0] != self.ssid[-1]:
            self.wpa_data = re.sub(r'ssid="(.*)"', f'ssid="{self.ssid[-1]}"', self.wpa_data)
            self.config_changes_logger.info(f"Changed 'ssid' from '{self.ssid[0]}' to '{self.ssid[-1]}'")
        
        if self.psk[0] != self.psk[-1]:
            self.wpa_data = re.sub(r'psk="(.*)"', f'psk="{self.psk[0]}"', self.wpa_data)
            self.config_changes_logger.info(f"Changed 'psk' from '{self.psk[-2]}' to '{self.psk[-1]}'")
        
        if self.priority[0] != self.priority[-1]:
            self.wpa_data = re.sub(r'priority=(.*)', f'priority={self.priority[-1]}', self.wpa_data)
            self.config_changes_logger.info(f"Changed 'priority' from '{self.priority[0]}' to '{self.priority[-1]}'")
        

        with open(self.wpa_supplicant_local, 'w') as wpa_file:
            wpa_file.write(self.wpa_data)

        self.controller.next_frame()

class ChangesLogPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.ssh_client = None
        self.sftp = None

        self.log_text = tk.Text(self)
        self.log_text.pack(fill="both", expand=True)

        reload_button = ttk.Button(self, text="Reload", command=self.reload)
        reload_button.pack()

        save_button = ttk.Button(self, text="Save", command=self.save_files_to_terminal_and_delete)
        save_button.pack()
        self.log_files = ['config_changes_cert.log', 'config_changes_T.log', 'config_changes_M.log', 'config_changes_apn.log', 'config_changes_wpa.log']  # List of log files

        self.read_and_display_log()

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
        self.sftp = self.ssh_client.open_sftp()

    
    def reload(self):
        self.log_text.delete("1.0", "end")
        self.read_and_display_log()

    def read_and_display_log(self):
        try:
            self.log_content = ""
            for log_file_name in self.log_files:
                with open(log_file_name, 'r') as log_file:
                    log_content = log_file.readlines()

                self.log_text.insert("end", ''.join(log_content))

        except FileNotFoundError:
            self.log_text.insert("1.0", "No log file found.")
        
    def save_files_to_terminal_and_delete(self):
        files = [['cert_manager.conf', '/home/g2k/.g2k_patch/production/G2K_Terminal/cert_manager.conf'],
                ['settings_T.py', '/home/g2k/.g2k_patch/production/G2K_Terminal/settings_T.py'],
                ['settings_M.py', '/home/g2k/.g2k_patch/production/G2K_MDB_Cashless/settings_M.py'],
                ['apn.cfg', '/home/g2k/.g2k_patch/apn.cfg'],
                ['wpa_supplicant-wlan0.conf', '/home/g2k/.g2k_patch/wpa_supplicant-wlan0.conf']]

        for i in files:
            self.sftp.put(i[0], i[1])
            print(f"Saved {i[0]}")

        commands = ['echo WhenInDoubt,SayNothingAndMoveOn.1973-2130 | sudo -k -S mv /home/g2k/.g2k_patch/apn.cfg /opt/4G_modems/',
                    'echo WhenInDoubt,SayNothingAndMoveOn.1973-2130 | sudo -k -S mv /home/g2k/.g2k_patch/wpa_supplicant-wlan0.conf /etc/wpa_supplicant/',
                    'chmod +x /home/g2k/.g2k_patch/production/patch_terminal.sh',
                    'echo WhenInDoubt,SayNothingAndMoveOn.1973-2130 | sudo -k -S /home/g2k/.g2k_patch/production/patch_terminal.sh',
                    'rm -rf /home/g2k/.g2k_patch/*']

        for command in commands:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print(f"Command '{commands.index(command)}' executed successfully")
            else:
                print(f"Command '{commands.index(command)}' failed with exit status {exit_status}")

        self.controller.delete_files()
        self.controller.next_frame()

class Generate_New_Password(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.ssh_client = None

        self.label_text = ttk.Label(self, text='Generate Password')
        self.label_text.pack(pady=30)

        self.generated_password = None

        generate_button = ttk.Button(self, text="Generate Password", command=self.print_pas)
        generate_button.pack(pady=10)

    def set_ssh_connection(self, ssh_client):
        self.ssh_client = ssh_client
    
    def print_pas(self):
        try:
            self.pas_entry.destroy()
            self.save_pas_button.destroy()
        except:
            pass

        alphabet = string.ascii_letters + string.digits
        self.generated_password = ''.join(secrets.choice(alphabet) for i in range(10))

        self.pas_entry = ttk.Entry(self)
        self.pas_entry.insert(0, self.generated_password)
        self.pas_entry.configure(state='readonly')
        self.pas_entry.pack()

        self.save_pas_button = ttk.Button(self, text="Save Password", command=self.save_pas)
        self.save_pas_button.pack(pady=10)


    def save_pas(self):
        if self.generated_password != None:
            command = "{ echo 'WhenInDoubt,SayNothingAndMoveOn.1973-2130'; echo 'g2k:"+str(self.generated_password)+"'; } | sudo -k -S chpasswd"
        else:
            print('NO password')
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print(f"Command executed password successfully")
        else:
            print(f"Command command password failed with exit status {exit_status}")
            print(stderr)
    
        
if __name__ == "__main__":
    app = MultiPageApp()
    app.mainloop()
