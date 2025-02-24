from PySide6.QtWidgets import QApplication, QLineEdit, QWidget, QFormLayout, QPushButton, QLabel, QVBoxLayout, QListWidget, QDialog, QDialogButtonBox
from PySide6.QtGui import QIntValidator
import sys
import os
import subprocess

SCRIPT_PATH = "./generated/intercept.py"
TEMP_DIR = "./generated"
rules = []

def generate_mitmproxy_script(rules):
    script = """
from mitmproxy import http
import json
import re

def set_value(data, path, value):
    for key in path.split(".")[:-1]:
        data = data.setdefault(key, {})
    data[path.split(".")[-1]] = value

def response(flow: http.HTTPFlow):
"""
    for rule in rules:
        url = rule['url']
        path = rule['path']
        repl_value = rule['repl_value']
        script += f"""
    if re.search(r"{url}", flow.request.pretty_url):
        data = json.loads(flow.response.text)
        set_value(data, "{path}", "{repl_value}")
        flow.response.text = json.dumps(data)
"""
    return script

def write_script(script):
    os.makedirs(TEMP_DIR, exist_ok=True)
    with open(SCRIPT_PATH, "w") as f:
        f.write(script)

def run_mitmproxy(port, rules):
    script = generate_mitmproxy_script(rules)
    write_script(script)
    try:
        subprocess.Popen([
            "mitmproxy", "--listen-port", str(port), "-s", SCRIPT_PATH
        ], stderr=subprocess.PIPE)
        return True, ""
    except Exception as e:
        return False, str(e)

def stop_mitmproxy():
    os.popen("killall mitmproxy")

def toggle_mitmproxy():
    global status
    if status == "not running":
        status = "running (make sure to route your traffic through the specified port)"
        port = port_input.text().strip() or "8080"
        success, error = run_mitmproxy(port, rules)
        if not success:
            update_status(f"Error: {error}")
        else:
            update_status(status)
    else:
        stop_mitmproxy()
        status = "not running"
        update_status(status)

def add_rule():
    dialog = RuleDialog()
    if dialog.exec():
        rule = dialog.get_values()
        if rule:
            rules.append(rule)
            update_rule_list()

def edit_rule(index):
    rule = rules[index]
    dialog = RuleDialog(rule)
    if dialog.exec():
        updated_rule = dialog.get_values()
        if updated_rule:
            rules[index] = updated_rule
            update_rule_list()

def remove_rule(index):
    if 0 <= index < len(rules):
        del rules[index]
        update_rule_list()

def update_rule_list():
    rule_list.clear()
    for i, rule in enumerate(rules):
        rule_list.addItem(f"Rule {i+1}: {rule['url']} -> {rule['path']} -> {rule['repl_value']}")

def update_status(status):
    status_label.setText(f"Status: {status}")
    start_btn.setText("Stop Listening" if status != "not running" else "Start Listening")

class RuleDialog(QDialog):
    def __init__(self, rule=None):
        super().__init__()
        self.setWindowTitle("Add/Edit Rule")
        self.setFixedSize(300, 200)
        self.layout = QFormLayout()
        self.url_input = QLineEdit()
        self.path_input = QLineEdit()
        self.repl_input = QLineEdit()
        if rule:
            self.url_input.setText(rule['url'])
            self.path_input.setText(rule['path'])
            self.repl_input.setText(rule['repl_value'])
        self.layout.addRow("URL (regex):", self.url_input)
        self.layout.addRow("JSON Path:", self.path_input)
        self.layout.addRow("Replace With:", self.repl_input)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)
        self.setLayout(self.layout)

    def get_values(self):
        url = self.url_input.text().strip()
        path = self.path_input.text().strip()
        repl_value = self.repl_input.text().strip()
        return {'url': url, 'path': path, 'repl_value': repl_value} if url and path and repl_value else None

app = QApplication(sys.argv)
win = QWidget()
win.setWindowTitle("httpatch")
layout = QVBoxLayout()
win.setMinimumWidth(600)
form_layout = QFormLayout()
port_input = QLineEdit()
port_input.setValidator(QIntValidator(0, 65535))
port_input.setPlaceholderText("8080")
form_layout.addRow("Port:", port_input)
start_btn = QPushButton("Start Listening")
start_btn.clicked.connect(toggle_mitmproxy)
form_layout.addRow(start_btn)
rule_list = QListWidget()
rule_list.itemDoubleClicked.connect(lambda item: edit_rule(rule_list.row(item)))
layout.addWidget(rule_list)
add_rule_btn = QPushButton("Add New Rule")
add_rule_btn.clicked.connect(add_rule)
layout.addWidget(add_rule_btn)
status_label = QLabel()
layout.addWidget(status_label)
layout.addLayout(form_layout)
status = "not running"
update_status(status)
win.setLayout(layout)
win.show()
sys.exit(app.exec())
