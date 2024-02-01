from flask import Flask, render_template,request, jsonify, redirect, url_for,Response
import subprocess
import json
import re
import time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw,send
import logging
import multiprocessing
import os

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.INFO,format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_log_data(log_file):
    with open(log_file, "r") as file:
        file.seek(0, os.SEEK_END)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield f"data: {line}\n\n"

def process_packet(packet):
    ip_packet = IP(packet.get_payload())
    
    if ip_packet.haslayer(TCP) and ip_packet.haslayer(Raw):
        payload = ip_packet[Raw].load.decode(errors="ignore")
        
        xss_elements = ["<script>", "</script>", "alert", "onerror","<", ">"]
        sql_elements = ["' OR '1", "OR", "1", "--"]
        original_payload = payload
        for element in xss_elements:
            if element in payload:
                logger.warning(f"XSS 공격 요소 '{element}' 탐지됨. 제거 중...")
                payload = payload.replace(element, "")
        
        for element in sql_elements:
            if element in payload:
                logger.warning(f"sql injection 공격 요소 '{element}' 탐지됨. 제거 중...")
                payload = payload.replace(element, "")
        
        if payload != original_payload:
            ip_packet[Raw].load = payload.encode()
            packet.set_payload(bytes(ip_packet))
    
        logger.info(f"패킷 정상 처리: {ip_packet.src} -> {ip_packet.dst}")
    packet.accept()


def packet_processor(queue_num):
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, process_packet)
    print(f"Starting packet processing in process {os.getpid()}...")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping packet processing...")
    finally:
        nfqueue.unbind()

def get_icmp_users_log(log_name):
    command = f"sudo dmesg -T | grep '{log_name}'"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    print(result.stdout)
    regex_pattern = (
        r'\[(\w+)\s+(\d+)월\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\] '
        fr'{log_name}: '
        r'IN=(\w+) '
        r'OUT=(\w+) '
        r'MAC=([0-9a-f:]+) '
        r'SRC=([\d.]+) '
        r'DST=([\d.]+) '
        r'LEN=(\d+) '
        r'TOS=([0-9a-fx]+) '
        r'PREC=([0-9a-fx]+) '
        r'TTL=(\d+) '
        r'ID=(\d+) '
        r'DF PROTO=(\w+) '
        r'(TYPE=(\d+) CODE=(\d+) ID=(\d+) SEQ=(\d+))?'
    )
    
    parsed_logs = []

    # 결과의 각 라인을 파싱
    for line in result.stdout.split('\n'):
        match = re.search(regex_pattern, line)
        if match:
            day_of_week, month, day, hour, minute, second, year, \
            in_interface, out_interface, mac, src_ip, dst_ip, length, \
            tos, prec, ttl, id, proto, *icmp_info = match.groups()

            time = f"{hour}:{minute}:{second}"
            parsed_log = (
                day_of_week, month, day, time, year, in_interface, 
                out_interface, mac, src_ip, dst_ip, length, tos, prec, 
                ttl, id, proto
            ) + tuple(icmp_info or ('-', '-', '-', '-'))
            parsed_logs.append(parsed_log)
    
    return parsed_logs


def get_users_log(log_name):
    command = f"sudo dmesg -T | grep {log_name}"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    regex_pattern = (
        r'\[(\w+)\s+(\d+)월\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\] '
        fr'{log_name}: '
        r'IN=(\w+) '
        r'OUT=(\w+) '
        r'MAC=([0-9a-f:]+) '
        r'SRC=([\d.]+) '
        r'DST=([\d.]+) '
        r'LEN=(\d+) '
        r'TOS=([0-9a-fx]+) '
        r'PREC=([0-9a-fx]+) '
        r'TTL=(\d+) '
        r'ID=(\d+) '
        r'DF PROTO=(\w+) '
        r'SPT=(\d+) '
        r'DPT=(\d+) '
        r'WINDOW=(\d+) '
        r'RES=([0-9a-fx]+) '
        r'(?:SYN|ACK|PSH|FIN|URGP=(\d+))?'
    )
    
    parsed_logs = []
    
    for line in result.stdout.split('\n'):
        match = re.search(regex_pattern, line)
        if match:
            day_of_week, month, day, hour, minute, second, year, *rest = match.groups()
            time = f"{hour}:{minute}:{second}"
            parsed_log = (day_of_week, month, time, year, *rest)
            parsed_logs.append(parsed_log)
    return parsed_logs


def get_iptables_rules_with_numbers():
    command = ["sudo", "iptables", "-nvL", "--line-numbers"]
    result = subprocess.run(command, capture_output=True, text=True)
    lines = result.stdout.split('\n')

    rules_dict = {}
    seen_rules = set()

    for line in lines:
        if line and line[0].isdigit():
            rule_data = line.split(None, 1)[1]

            if rule_data not in seen_rules:
                rules_dict[line] = 0
                seen_rules.add(rule_data)
            else:
                rules_dict[line] = 1

    return rules_dict

def get_conntrack_session(option, input_value):
    if not input_value and option != "all":
        return ""

    if option != "all":
        command = f"sudo conntrack -L | grep '{option}={input_value}'"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
    else:
        command = ["sudo", "conntrack", "-L"]
        result = subprocess.run(command, capture_output=True, text=True)

    conntrack_sessions = []
    regex_pattern = (
        r'(\w+)\s+(\d+)\s+(\d+)\s+(\w+)\s+'
        r'src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)\s+'
        r'src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)\s+'
        r'\[(\w+)\]\s+mark=(\d+)\s+use=(\d+)'
    )

    for line in result.stdout.split('\n'):
        match = re.search(regex_pattern, line)
        if match:
            protocol_name, protocol_number, id, status, \
            first_src_ip, first_dst_ip, first_src_port, first_dst_port, \
            second_src_ip, second_dst_ip, second_src_port, second_dst_port, \
            assured, mark, use = match.groups()
            
            session_data = (protocol_name, protocol_number, id, status, 
                            first_src_ip, first_dst_ip, first_src_port, first_dst_port, 
                            second_src_ip, second_dst_ip, second_src_port, second_dst_port, 
                            assured, mark, use)
            
            conntrack_sessions.append(session_data)
    
    return conntrack_sessions


@app.route("/",methods=["POST","GET"])
def home():
    rules = get_iptables_rules_with_numbers()
    return render_template("index.html", rules=rules)


@app.route("/log",methods=["GET","POST"])
def log():
    if request.method == "POST" and "log_name" in request.form:
        log_name = request.form.get("log_name")
        if log_name == "ILOG":
            log_result = get_icmp_users_log(log_name)
        elif log_name == "TLOG" or log_name == "ULOG":
            log_result = get_users_log(log_name)
        else:
            log_result = get_users_log(log_name)
    else:
        log_result = get_users_log("TLOG")

    return render_template("set_log.html", log_result=log_result)

@app.route("/session",methods=["GET","POST"])
def session():
    if request.method == "POST" and "conn_session" in request.form:
        option = request.form.get("option")
        input_value = request.form.get("input_value")
        conn_session = get_conntrack_session(option, input_value)
    else:
        conn_session = get_conntrack_session("all", "")

    return render_template("set_session.html", conn_session=conn_session)


@app.route("/delete_rule/<string:rule_number>", methods=["POST"])
def delete_rule(rule_number):
    if rule_number == "<span":
        new_rule = rule_number.substring(rule_number.indexOf(';') + 1).trim()
        try:
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", new_rule], check=True)
            return jsonify(success=True, message=f"Rule {rule_number} deleted successfully")
        except Exception as e:
            return jsonify(success=False, message=str(e))
    else:
        try:
            subprocess.run(["sudo", "iptables", "-D", "FORWARD", rule_number], check=True)
            return jsonify(success=True, message=f"Rule {rule_number} deleted successfully")
        except Exception as e:
            return jsonify(success=False, message=str(e))


@app.route("/block_traffic", methods=["POST"])
def block_traffic():
    protocol = request.form.get("protocol")
    source_ip = request.form.get("source_ip")
    destination_ip = request.form.get("destination_ip")
    sport = request.form.get("sport")
    dport = request.form.get("dport")
    rootcommand = ["sudo", "iptables", "-A", "FORWARD"]
    if protocol == "icmp":        
            rootcommand.extend(["-p",protocol])
            command = ["sudo", "iptables", "-A", "FORWARD", "-p", "icmp"]
            if source_ip:
                command.extend(["-s", source_ip])
                rootcommand.extend(["-s",source_ip])
            if destination_ip:
                rootcommand.extend(["-d",destination_ip])
                command.extend(["-d", destination_ip])
            command.append("-j")
            command.append("DROP")
            rootcommand.extend(["-j","LOG","--log-prefix","ILOG: ","--log-level","4"])
            print(rootcommand)
            subprocess.run(rootcommand)

            subprocess.run(command)
            return redirect(url_for('home'))
    
    if protocol == "tcp":
        command = ["sudo", "iptables", "-A", "FORWARD", "-p", "tcp"]
        if source_ip:
            rootcommand.extend(["-s",source_ip])
            command.extend(["-s", source_ip])
        if destination_ip:
            rootcommand.extend(["-d",destination_ip])
            command.extend(["-d", destination_ip])
        if sport:
            command.extend(["--sport", sport])
        if dport:
            command.extend(["--dport", dport])

        command.extend(["-j", "DROP"])
        rootcommand.extend(["-j","LOG","--log-prefix","TLOG: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(command)
        return redirect(url_for('home'))
    
    if protocol =="udp":
        command = ["sudo", "iptables", "-A", "FORWARD", "-p", "udp"]
        if source_ip:
            rootcommand.extend(["-s",source_ip])
            command.extend(["-s", source_ip])
        if destination_ip:
            rootcommand.extend(["-d",destination_ip])
            command.extend(["-d", destination_ip])
        if sport:
            command.extend(["--sport", sport])
        if dport:
            command.extend(["--dport", dport])

        command.extend(["-j", "DROP"])
        rootcommand.extend(["-j","LOG","--log-prefix","ULOG: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(command)
        return redirect(url_for('home'))
    
    if protocol == "all":
        ip_to_block = source_ip
        rootcommand.extend(["-s",ip_to_block])
        rootcommand.extend(["-j","LOG","--log-prefix","ROOT: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(["sudo","iptables","-A","FORWARD","-s",ip_to_block,"-j","DROP"])
    
    return redirect(url_for('home'))

@app.route("/allow_traffic", methods=["POST"])
def allow_traffic():
    protocol = request.form.get("protocol")
    source_ip = request.form.get("source_ip")
    destination_ip = request.form.get("destination_ip")
    sport = request.form.get("sport")
    dport = request.form.get("dport")
    rootcommand = ["sudo", "iptables", "-A", "FORWARD"]
    if protocol == "icmp":        
            rootcommand.extend(["-p",protocol])
            command = ["sudo", "iptables", "-A", "FORWARD", "-p", "icmp"]
            if source_ip:
                command.extend(["-s", source_ip])
                rootcommand.extend(["-s",source_ip])
            if destination_ip:
                rootcommand.extend(["-d",destination_ip])
                command.extend(["-d", destination_ip])
            command.append("-j")
            command.append("ACCEPT")
            rootcommand.extend(["-j","LOG","--log-prefix","ILOG: ","--log-level","4"])
            subprocess.run(rootcommand)

            subprocess.run(command)
            return redirect(url_for('home'))
    
    if protocol == "tcp":
        command = ["sudo", "iptables", "-A", "FORWARD", "-p", "tcp"]
        if source_ip:
            rootcommand.extend(["-s",source_ip])
            command.extend(["-s", source_ip])
        if destination_ip:
            rootcommand.extend(["-d",destination_ip])
            command.extend(["-d", destination_ip])
        if sport:
            command.extend(["--sport", sport])
        if dport:
            command.extend(["--dport", dport])

        command.extend(["-j", "ACCEPT"])
        rootcommand.extend(["-j","LOG","--log-prefix","TLOG: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(command)
        return redirect(url_for('home'))
    
    if protocol =="udp":
        command = ["sudo", "iptables", "-A", "FORWARD", "-p", "udp"]
        if source_ip:
            rootcommand.extend(["-s",source_ip])
            command.extend(["-s", source_ip])
        if destination_ip:
            rootcommand.extend(["-d",destination_ip])
            command.extend(["-d", destination_ip])
        if sport:
            command.extend(["--sport", sport])
        if dport:
            command.extend(["--dport", dport])

        command.extend(["-j", "ACCEPT"])
        rootcommand.extend(["-j","LOG","--log-prefix","ULOG: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(command)
        return redirect(url_for('home'))
    
    if protocol == "all":
        ip_to_block = source_ip
        rootcommand.extend(["-s",ip_to_block])
        rootcommand.extend(["-j","LOG","--log-prefix","ROOT: ","--log-level","4"])
        subprocess.run(rootcommand)
        subprocess.run(["sudo","iptables","-A","FORWARD","-s",ip_to_block,"-j","ACCEPT"])
    
    return redirect(url_for('home'))


@app.route("/setlog",methods=["POST"])
def set_log():
    log_name = request.form.get("log_name")
    log_level = request.form.get("log_level")
    command = ["sudo", "iptables", "-A", "FORWARD", "-p", "tcp", "--dport", "80", "-j", "LOG"]
    if log_name:
        command.extend(["--log-prefix", log_name + ": "])
    if log_level:
        command.extend(["--log-level", log_level])
    subprocess.run(command)
    return redirect(url_for('log'))


@app.route('/update_rule_position', methods=['POST'])
def update_rule_position():
    rule_number = request.form.get("rule_number")
    new_position = request.form.get('new_position')
    rule_spec = request.form.get('rule_spec')

    try:
        delete_command = ["sudo", "iptables", "-D", "FORWARD", str(rule_number)]
        subprocess.run(delete_command, check=True)

        insert_command = ["sudo", "iptables", "-I", "FORWARD", str(new_position)] + rule_spec.split()
        subprocess.run(insert_command, check=True)

        return redirect(url_for('home'))
    except subprocess.CalledProcessError as e:
        return redirect(url_for('home'))
    
@app.route("/web",methods=["POST","GET"])
def web():    
    return render_template("web.html")

@app.route('/log-stream')
def log_stream():
    log_file = "app.log"
    return Response(generate_log_data(log_file), mimetype="text/event-stream")
if __name__ == "__main__":
    queue_num = 4
    packet_process = multiprocessing.Process(target=packet_processor, args=(queue_num,))
    packet_process.start()

    try:
        app.run(debug=True)
    finally:
        packet_process.terminate()
        packet_process.join()