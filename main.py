import logging
import subprocess
import os
import stat
import re
import socket
import smtplib
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import psutil
import platform
import tkinter as tk
from tkinter import messagebox
from tkinter.ttk import Progressbar

# Configuração do logging
logging.basicConfig(filename='security_check.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configurações do e-mail
smtp_server = 'smtp.gmail.com'
smtp_port = 587
sender_email = 'yuuhekurenai@gmail.com'
receiver_email = 'celestino.orbital@gmail.com'

# Mapeamento de versões conhecidas do Linux
linux_versions = {
    'Ubuntu': ['18.04', '20.04'],
    'CentOS': ['7', '8'],
    # Adicione outras distribuições e versões conhecidas do Linux
}

# Mapeamento de versões conhecidas do Windows
windows_versions = {
    'Windows 7': ['Service Pack 1'],
    'Windows 10': ['2004', '20H2', '21H1'],
    'Windows 11': ['22000.51']
    # Adicione outras versões conhecidas do Windows
}

# Mapeamento de versões conhecidas do MacOS
macos_versions = {
    'Mojave': ['10.14'],
    'Catalina': ['10.15'],
    'Big Sur': ['11.0', '11.1', '11.2', '11.3', '11.4']
    # Adicione outras versões conhecidas do MacOS
}


# Verificação de versões do Linux
def check_linux_version(log_list):
    log_list.append("Verificando versão do Linux...")
    distribution = get_linux_distribution()
    if distribution in linux_versions:
        installed_version = get_linux_version(distribution)
        if installed_version in linux_versions[distribution]:
            log_list.append(f'A distribuição {distribution} está em uma versão vulnerável: {installed_version}')
    log_list.append("Versão do Linux verificada.")


# Verificação de versões do Windows
def check_windows_version(log_list):
    log_list.append("Verificando versão do Windows...")
    version = get_windows_version()
    if version in windows_versions:
        installed_version = get_installed_windows_version()
        if installed_version in windows_versions[version]:
            log_list.append(f'O Windows está em uma versão vulnerável: {installed_version}')
    log_list.append("Versão do Windows verificada.")


# Verificação de versões do MacOS
def check_macos_version(log_list):
    log_list.append("Verificando versão do MacOS...")
    version = get_macos_version()
    if version in macos_versions:
        installed_version = get_installed_macos_version()
        if installed_version in macos_versions[version]:
            log_list.append(f'O MacOS está em uma versão vulnerável: {installed_version}')
    log_list.append("Versão do MacOS verificada.")


# Função para obter a distribuição Linux instalada
def get_linux_distribution():
    output = subprocess.check_output(['lsb_release', '-si'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    return output


# Função para obter a versão da distribuição Linux
def get_linux_version(distribution):
    output = subprocess.check_output(['lsb_release', '-sr'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    return output


# Função para obter a versão do Windows
def get_windows_version():
    output = subprocess.check_output(['wmic', 'os', 'get', 'Caption'], stderr=subprocess.DEVNULL).decode(
        'utf-8').strip()
    match = re.search(r'Caption\s+([\w\s]+)', output)
    if match:
        return match.group(1).strip()
    return None


# Função para obter a versão do Windows instalada
def get_installed_windows_version():
    output = subprocess.check_output(['ver'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    match = re.search(r'\[Version\s([\d.]+)', output)
    if match:
        return match.group(1).strip()
    return None


# Função para obter a versão do MacOS
def get_macos_version():
    output = subprocess.check_output(['sw_vers', '-productVersion'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    return output


# Função para obter a versão do MacOS instalada
def get_installed_macos_version():
    output = subprocess.check_output(['sw_vers', '-productVersion'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    return output


# Verificação de compatibilidade do sistema com o verificador
def check_system_compatibility(log_list):
    log_list.append("Verificando compatibilidade do sistema...")
    operating_system = platform.system()
    if operating_system == 'Linux':
        log_list.append("Sistema compatível com o verificador.")
    elif operating_system == 'Windows':
        log_list.append("Sistema compatível com o verificador.")
    elif operating_system == 'Darwin':
        log_list.append("Sistema compatível com o verificador.")
    else:
        log_list.append("Sistema não compatível com o verificador.")
    log_list.append("Compatibilidade do sistema verificada.")


# Verificação de vulnerabilidades de rede
def check_network_vulnerabilities(log_list):
    log_list.append("Verificando vulnerabilidades de rede...")
    open_ports = get_open_ports()
    known_vulnerable_ports = [22, 80, 443]  # Exemplo de portas conhecidas por serem vulneráveis

    vulnerable_ports = []
    for port in open_ports:
        if port in known_vulnerable_ports:
            vulnerable_ports.append(port)

    if vulnerable_ports:
        log_list.append("Foram encontradas vulnerabilidades de rede.")
        send_network_alert_email(vulnerable_ports)
    else:
        log_list.append("Nenhuma vulnerabilidade de rede encontrada.")
    log_list.append("Vulnerabilidades de rede verificadas.")


# Função para obter as portas abertas na máquina
def get_open_ports():
    open_ports = []
    output = subprocess.check_output(['netstat', '-lnt'], stderr=subprocess.DEVNULL).decode('utf-8')
    lines = output.split('\n')[2:]  # Ignora as duas primeiras linhas do output
    for line in lines:
        if line:
            parts = line.split()
            if parts[0] == 'tcp':
                port = int(parts[3].split(':')[-1])
                open_ports.append(port)

    return open_ports


# Função para corrigir falhas comuns de segurança de rede
def fix_common_network_security_issues():
    # Exemplo: Fechar a porta 22 (SSH) se estiver aberta
    if 22 in get_open_ports():
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'DROP'])

    # Adicione outras correções de segurança de rede conforme necessário


# Função para verificar a segurança dos dados dos usuários
def check_user_data_security(log_list):
    log_list.append("Verificando segurança dos dados dos usuários...")
    users = get_system_users()
    sensitive_files = ['/home/user1/private.txt',
                       '/home/user2/passwords.txt']  # Exemplo de arquivos sensíveis dos usuários

    vulnerable_files = []
    for user in users:
        for file in sensitive_files:
            if check_file_permissions(file) and check_file_owner(file, user):
                vulnerable_files.append(f'O arquivo {file} do usuário {user} está inseguro.')

    log_list.append("Segurança dos dados dos usuários verificada.")
    return vulnerable_files


# Função para obter os usuários do sistema
def get_system_users():
    users = []
    output = subprocess.check_output(
        ['awk', '-F:', '{ if ($3 >= 1000 && $7 != "/usr/sbin/nologin") print $1 }', '/etc/passwd'],
        stderr=subprocess.DEVNULL).decode('utf-8')
    lines = output.split('\n')
    for line in lines:
        if line:
            users.append(line.strip())

    return users


# Função para verificar as permissões do arquivo
def check_file_permissions(path):
    permissions = stat.S_IMODE(os.lstat(path).st_mode)
    if permissions & stat.S_IWOTH:
        return False
    return True


# Função para verificar o proprietário do arquivo
def check_file_owner(path, owner):
    file_owner = os.stat(path).st_uid
    output = subprocess.check_output(['id', '-un', str(file_owner)], stderr=subprocess.DEVNULL).decode('utf-8').strip()
    if output == owner:
        return True
    return False


# Função para enviar e-mail
def send_email(subject, body):
    try:
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')

        if not smtp_username or not smtp_password:
            raise ValueError("As credenciais do SMTP não foram configuradas corretamente.")

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = smtp_username
        msg['To'] = receiver_email

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        logging.info("E-mail enviado: Assunto='%s'", subject)

    except Exception as e:
        logging.error("Erro ao enviar e-mail: %s", str(e))
        raise

# Função para enviar e-mail de alerta de rede
def send_network_alert_email(vulnerable_ports):
    subject = 'ALERTA DE SEGURANÇA: Vulnerabilidades de Rede Detectadas'
    body = 'Foram detectadas as seguintes vulnerabilidades de rede:\n\n'
    for port in vulnerable_ports:
        body += f'A porta {port} está aberta e é conhecida por ser vulnerável.\n'
    send_email(subject, body)


# Função para apagar executáveis maliciosos
def remove_malicious_executables():
    malicious_files = ['/path/to/file1', '/path/to/file2']  # Exemplo de executáveis maliciosos

    for file in malicious_files:
        try:
            os.remove(file)
        except OSError:
            pass


# Função para verificar e remover o cryptojacking
def check_and_remove_cryptojacking():
    cryptojacking_processes = []

    # Encontra processos suspeitos relacionados ao cryptojacking
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        cmdline = process.info['cmdline']
        if cmdline and 'coinhive' in ' '.join(cmdline).lower():
            cryptojacking_processes.append(process)

    if cryptojacking_processes:
        # Finaliza os processos relacionados ao cryptojacking
        for process in cryptojacking_processes:
            process.terminate()

        # Aguarda a finalização dos processos
        psutil.wait_procs(cryptojacking_processes, timeout=5)


# Classe do manipulador de solicitação HTTP
class LoadBalancerHandler(BaseHTTPRequestHandler):
    backend_servers = [('localhost', 8000), ('localhost', 8001)]  # Exemplo de servidores backend

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        backend_index = self.path.count('/') % len(self.backend_servers)
        backend_server = self.backend_servers[backend_index]
        self.proxy_request(backend_server)

    def proxy_request(self, backend_server):
        try:
            backend_host, backend_port = backend_server
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_socket.connect((backend_host, backend_port))

            request_data = self.requestline + '\r\n'
            for header in self.headers:
                request_data += header + ': ' + self.headers[header] + '\r\n'
            request_data += '\r\n'

            backend_socket.sendall(request_data.encode())

            response_data = b''
            while True:
                data = backend_socket.recv(1024)
                if not data:
                    break
                response_data += data

            self.wfile.write(response_data)
            backend_socket.close()
        except:
            self.send_error(500, 'Internal Server Error')


# Classe do servidor HTTP do balanceador de carga
class LoadBalancerServer(ThreadingMixIn, HTTPServer):
    pass


# Configuração de limites de conexão usando iptables
def configure_connection_limits():
    ports = [80, 443]  # Exemplo de portas TCP relevantes

    for port in ports:
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '--dport', str(port), '-m', 'connlimit',
                        '--connlimit-above', '100', '-j', 'DROP'])


# Configuração do sistema IDS/IPS usando fail2ban
def configure_ids_ips():
    config_file = '/etc/fail2ban/jail.local'
    with open(config_file, 'a') as file:
        file.write('\n')
        file.write('[http-attack]\n')
        file.write('enabled = true\n')
        file.write('port = 80,443\n')
        file.write('filter = http-attack\n')
        file.write('logpath = /var/log/apache2/access.log\n')
        file.write('maxretry = 100\n')
        file.write('findtime = 600\n')
        file.write('bantime = 3600\n')

    subprocess.run(['systemctl', 'restart', 'fail2ban'])


# Função para verificar se a rede Wi-Fi usa WPA2 ou WPA3
def is_wifi_wpa2_wpa3_encryption_used():
    output = subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL).decode('utf-8')
    match_wpa2 = re.search(r'Encryption key:on\n\s*IE:\sWPA2\n', output)
    match_wpa3 = re.search(r'Encryption key:on\n\s*IE:\s802\.11i/WPA3\n', output)
    return match_wpa2 or match_wpa3

# Função para verificar a força da senha da rede Wi-Fi
def is_wifi_password_strong():
    output = subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL).decode('utf-8')
    match_key = re.search(r'Encryption key:on\n\s*Access Point:\s[0-9A-F:]+\s\s*\n\s*IE:\sUnknown:............(...........)', output)
    if match_key:
        password = match_key.group(1)
        # Adicione aqui as verificações de complexidade da senha, por exemplo:
        # Verificar o tamanho mínimo da senha, presença de caracteres especiais, letras maiúsculas e minúsculas, etc.
        return len(password) >= 12 and any(char.isdigit() for char in password) and any(char.isalpha() for char in password)
    return False

# Função para verificar dispositivos desconhecidos na rede Wi-Fi
def check_unknown_devices_connected():
    output = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL).decode('utf-8')
    unknown_devices = []
    for line in output.split('\n'):
        if 'incomplete' in line.lower():
            # Identifica dispositivos desconhecidos na tabela ARP
            match_ip = re.search(r'\(([0-9.]+)\)', line)
            if match_ip:
                unknown_devices.append(match_ip.group(1))
    return unknown_devices

# Função para verificar a segurança da rede Wi-Fi
def check_wifi_security(log_list):
    log_list.append("Verificando segurança da rede Wi-Fi...")

    if is_wifi_wpa2_wpa3_encryption_used():
        log_list.append("A rede Wi-Fi usa criptografia WPA2 ou WPA3.")
    else:
        log_list.append("A rede Wi-Fi não usa criptografia WPA2 ou WPA3.")

    if is_wifi_password_strong():
        log_list.append("A senha da rede Wi-Fi é forte.")
    else:
        log_list.append("A senha da rede Wi-Fi não é forte.")

    unknown_devices = check_unknown_devices_connected()
    if unknown_devices:
        log_list.append("Dispositivos desconhecidos conectados à rede Wi-Fi:")
        for device in unknown_devices:
            log_list.append(device)
    else:
        log_list.append("Não há dispositivos desconhecidos conectados à rede Wi-Fi.")

    log_list.append("Segurança da rede Wi-Fi verificada.")

# Função para verificar a segurança ao executar o programa
def check_security(log_list, progress_bar, log_text, update_status, update_log_and_status):
    try:
        # Verificação de compatibilidade do sistema
        update_status("Verificando compatibilidade do sistema...")
        check_system_compatibility(log_list)
        operating_system = platform.system()

        if operating_system == 'Linux':
            # Verificação de versões do Linux
            update_status("Verificando versão do Linux...")
            check_linux_version(log_list)

            # Verificação de vulnerabilidades de rede
            update_status("Verificando vulnerabilidades de rede...")
            network_vulnerabilities = check_network_vulnerabilities(log_list)

            # Verificação de segurança dos dados dos usuários
            update_status("Verificando segurança dos dados dos usuários...")
            user_data_security = check_user_data_security(log_list)

            # Verificação de segurança da rede Wi-Fi
            update_status("Verificando segurança da rede Wi-Fi...")
            wifi_security = check_wifi_security(log_list)

            # Outras verificações específicas do Linux podem ser adicionadas aqui

        elif operating_system == 'Windows':
            # Verificação de versões do Windows
            update_status("Verificando versão do Windows...")
            check_windows_version(log_list)
            # Outras verificações específicas do Windows podem ser adicionadas aqui

        elif operating_system == 'Darwin':
            # Verificação de versões do MacOS
            update_status("Verificando versão do MacOS...")
            check_macos_version(log_list)
            # Outras verificações específicas do MacOS podem ser adicionadas aqui

        # Verificação de outras etapas comuns, independentemente do sistema operacional
        update_status("Verificando outras etapas comuns...")
        check_and_remove_cryptojacking()
        remove_malicious_executables()
        configure_connection_limits()
        configure_ids_ips()

        # Atualizar o progresso da barra
        progress_bar.stop()
        progress_bar["value"] = 100

        # Atualizar a lista de log e o status da verificação
        window.after(100, update_log_and_status)

    except Exception as e:
        log_list.append("Ocorreu um erro durante a verificação de segurança:")
        log_list.append(str(e))
        logging.exception("Erro durante a verificação de segurança:")
        update_log_and_status()



# Função para atualizar a lista de log
def update_log_list(log_list, log_text):
    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)
    for item in log_list:
        log_text.insert(tk.END, item + "\n")
    log_text.config(state=tk.DISABLED)


# Função para iniciar a verificação de segurança
def start_security_check(progress_bar, log_text, status_label):
    progress_bar.start()

    # Função para atualizar o status da verificação
    def update_status(status):
        status_label.config(text=status)

    log_list = []

    # Função para atualizar a lista de log e o status da verificação
    def update_log_and_status():
        update_log_list(log_list, log_text)
        status_label.config(text="Verificação de segurança concluída.")
        messagebox.showinfo('Concluído', 'A verificação de segurança foi concluída.')

    # Chama a função para verificar a segurança em segundo plano
    window.after(100, lambda: check_security(log_list, progress_bar, log_text, update_status, update_log_and_status))

# Função para cancelar a verificação de segurança
def cancel_security_check(progress_bar):
    progress_bar.stop()
    messagebox.showinfo('Cancelado', 'A verificação de segurança foi cancelada.')


# Cria a janela principal do aplicativo
window = tk.Tk()
window.title('Verificação de Segurança')
window.geometry('400x300')

# Cria o Label para exibir o status da verificação
status_label = tk.Label(window, text="Aguardando início da verificação...")
status_label.pack(pady=10)

# Cria o botão de início da verificação
start_button = tk.Button(window, text='Iniciar Verificação',
                         command=lambda: start_security_check(progress_bar, log_text, status_label))
start_button.pack(pady=10)

# Cria o botão de cancelamento da verificação
cancel_button = tk.Button(window, text='Cancelar Verificação', command=lambda: cancel_security_check(progress_bar))
cancel_button.pack(pady=10)

# Cria a barra de progresso
progress_bar = Progressbar(window, length=300, mode="indeterminate")  # Modo indeterminado
progress_bar.pack(pady=10)

# Cria o Label para exibir o resultado final da verificação
result_label = tk.Label(window, text="", fg="green")
result_label.pack(pady=10)

# Cria a lista de log
log_text = tk.Text(window, height=10, state=tk.DISABLED)
log_text.pack(pady=10)

window.mainloop()
