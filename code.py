import re
import sys
import json
import hashlib
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QProgressBar, QTableWidget, QTableWidgetItem, QTabWidget,
    QStatusBar, QMessageBox, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime, QTimer
from PyQt5.QtGui import QFont, QColor, QTextCursor
import requests

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"


class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(str, str, str)  # 结果，错误，文件路径
    progress_updated = pyqtSignal(int, str)  # 进度，状态信息

    def __init__(self, api_key, prompt, file_queue, mode, cache):
        super().__init__()
        self.api_key = api_key
        self.prompt = prompt
        self.file_queue = file_queue
        self.mode = mode
        self.cache = cache
        self.is_running = True

    def run(self):
        try:
            total_files = len(self.file_queue)
            for index, file_path in enumerate(self.file_queue):
                if not self.is_running:
                    break

                self.progress_updated.emit(int((index / total_files) * 100), f"正在处理: {os.path.basename(file_path)}")

                # 检查缓存
                cached = self.check_cache(file_path)
                if cached:
                    self.analysis_complete.emit(cached['result'], "", file_path)
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    self.analysis_complete.emit("", f"文件读取失败: {str(e)}", file_path)
                    continue

                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}"
                }

                data = {
                    "messages": [
                        {"role": "system", "content": self.prompt},
                        {"role": "user", "content": content}
                    ],
                    "model": "deepseek-chat",
                    "temperature": 0.3
                }

                try:
                    response = requests.post(DEEPSEEK_API_URL, headers=headers, json=data)
                    result = response.json()
                    analysis_result = result['choices'][0]['message']['content']
                    self.save_to_cache(file_path, analysis_result)
                    self.analysis_complete.emit(analysis_result, "", file_path)
                except Exception as e:
                    self.analysis_complete.emit("", f"API错误: {str(e)}", file_path)

            self.progress_updated.emit(100, "处理完成")
        except Exception as e:
            self.analysis_complete.emit("", f"线程错误: {str(e)}", "")

    def check_cache(self, file_path):
        file_hash = self.get_file_hash(file_path)
        return self.cache.get(f"{self.mode}_{file_hash}") if file_hash else None

    def save_to_cache(self, file_path, result):
        file_hash = self.get_file_hash(file_path)
        if file_hash:
            self.cache[f"{self.mode}_{file_hash}"] = {
                "result": result,
                "timestamp": QDateTime.currentDateTime().toString()
            }

    def get_file_hash(self, file_path):
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            return None

    def stop(self):
        self.is_running = False


class CodeAuditTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.vulnerabilities = []
        self.cache = {}
        self.current_files = []
        self.active_button = None
        self.init_ui()
        self.set_stylesheet()

    def init_ui(self):
        self.setWindowTitle('自动化代码审计系统 by liuty v3.0')
        self.setGeometry(300, 300, 1200, 800)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # 顶部控制栏
        control_layout = QHBoxLayout()
        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("DeepSeek API密钥...")
        self.api_input.setEchoMode(QLineEdit.Password)

        # 文件列表控件
        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.ExtendedSelection)
        add_file_btn = QPushButton("添加文件")
        add_file_btn.clicked.connect(self.add_files)
        add_folder_btn = QPushButton("添加目录")
        add_folder_btn.clicked.connect(self.add_folder)
        clear_list_btn = QPushButton("清空列表")
        clear_list_btn.clicked.connect(self.clear_file_list)

        file_btn_layout = QVBoxLayout()
        file_btn_layout.addWidget(add_file_btn)
        file_btn_layout.addWidget(add_folder_btn)
        file_btn_layout.addWidget(clear_list_btn)

        control_layout.addWidget(QLabel("API密钥:"))
        control_layout.addWidget(self.api_input)
        control_layout.addWidget(QLabel("待审文件:"))
        control_layout.addWidget(self.file_list)
        control_layout.addLayout(file_btn_layout)
        layout.addLayout(control_layout)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setAlignment(Qt.AlignCenter)
        self.progress.hide()
        self.status_label = QLabel()
        layout.addWidget(self.progress)
        layout.addWidget(self.status_label)

        # 功能按钮
        btn_layout = QHBoxLayout()
        self.audit_btn = QPushButton("代码审计")
        self.decode_btn = QPushButton("AI解码")
        self.extract_btn = QPushButton("提取信息")
        self.stop_btn = QPushButton("停止处理")
        self.clear_cache_btn = QPushButton("清理缓存")
        btn_layout.addWidget(self.audit_btn)
        btn_layout.addWidget(self.decode_btn)
        btn_layout.addWidget(self.extract_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.clear_cache_btn)
        layout.addLayout(btn_layout)

        # 结果展示区
        self.tab_widget = QTabWidget()
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels(["文件", "类型", "风险等级", "位置", "详情", "修复建议"])
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.tab_widget.addTab(self.result_area, "实时分析")
        self.tab_widget.addTab(self.vuln_table, "漏洞汇总")
        layout.addWidget(self.tab_widget)

        # 信号连接
        self.audit_btn.clicked.connect(lambda: self.start_analysis("audit"))
        self.decode_btn.clicked.connect(lambda: self.start_analysis("decode"))
        self.extract_btn.clicked.connect(self.extract_sensitive_info)
        self.stop_btn.clicked.connect(self.stop_processing)
        self.clear_cache_btn.clicked.connect(self.clear_cache)

        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # 初始化按钮样式
        self.reset_button_styles()

    def set_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D2D;
            }
            QLineEdit, QTextEdit, QTableWidget, QListWidget {
                background-color: #404040;
                color: #FFFFFF;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton {
                background-color: #007BFF;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-size: 14px;
                min-width: 100px;
                transition: background-color 0.3s ease;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton[state="active"] {
                background-color: #00CC88;
            }
            QPushButton[state="completed"] {
                background-color: #4CAF50;
            }
            QPushButton[state="error"] {
                background-color: #FF4444;
            }
            QProgressBar {
                background: #404040;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
                height: 20px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #00FF88;
                border-radius: 3px;
            }
            QHeaderView::section {
                background-color: #007BFF;
                color: white;
                padding: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #4A4A4A;
            }
            QTabBar::tab {
                background: #404040;
                color: #FFFFFF;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #007BFF;
            }
        """)
        font = QFont("微软雅黑", 10)
        self.setFont(font)

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择文件", "", "All Files (*)")
        if files:
            self.file_list.addItems(files)
            self.current_files = [self.file_list.item(i).text() for i in range(self.file_list.count())]

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择目录")
        if folder:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    self.file_list.addItem(path)
            self.current_files = [self.file_list.item(i).text() for i in range(self.file_list.count())]

    def clear_file_list(self):
        self.file_list.clear()
        self.current_files = []

    def reset_button_styles(self):
        for btn in [self.audit_btn, self.decode_btn, self.extract_btn]:
            btn.setStyleSheet("")
        self.active_button = None

    def start_analysis(self, mode):
        self.reset_button_styles()
        btn = getattr(self, f"{mode}_btn", None)
        if btn:
            btn.setProperty("state", "active")
            btn.style().polish(btn)

        api_key = self.api_input.text()
        selected_files = [self.file_list.item(i).text() for i in range(self.file_list.count())]

        if not api_key:
            QMessageBox.warning(self, "警告", "请先输入API密钥！")
            return
        if not selected_files:
            QMessageBox.warning(self, "警告", "请选择要分析的文件！")
            return

        prompts = {
            "audit": """请严格按以下格式进行代码安全审计：
            [漏洞类型]: 
            [风险等级]: (高危/中危/低危)
            [位置]: 文件:行号
            [详情]: 
            [修复建议]: 
            -------------------------""",
            "decode": """请分析以下加密内容：
            1. 加密算法识别
            2. 解密尝试
            3. 安全性评估
            4. 改进建议"""
        }

        self.progress.show()
        self.status_label.show()
        self.analysis_thread = AnalysisThread(api_key, prompts[mode], selected_files, mode, self.cache)
        self.analysis_thread.progress_updated.connect(self.update_progress)
        self.analysis_thread.analysis_complete.connect(self.handle_result)
        self.analysis_thread.start()
        self.status_bar.showMessage("分析进行中...")

    def update_progress(self, value, message):
        self.progress.setValue(value)
        self.status_label.setText(message)

    def handle_result(self, result, error, file_path):
        if error:
            self.status_bar.showMessage(f"{os.path.basename(file_path)} 处理失败: {error}")
            QMessageBox.critical(self, "错误", f"{os.path.basename(file_path)} 处理失败: {error}")
        else:
            self.result_area.append(f"\n🔍 文件分析结果：{os.path.basename(file_path)}\n{result}")
            self.parse_vulnerabilities(result, file_path)
            self.highlight_keywords(result)

    def parse_vulnerabilities(self, text, file_path):
        current_vuln = {}
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith('[漏洞类型]:'):
                current_vuln = {'file': file_path, 'type': line.split(':', 1)[1].strip()}
            elif line.startswith('[风险等级]:'):
                current_vuln['level'] = line.split(':', 1)[1].strip()
            elif line.startswith('[位置]:'):
                current_vuln['location'] = line.split(':', 1)[1].strip()
            elif line.startswith('[详情]:'):
                current_vuln['detail'] = line.split(':', 1)[1].strip()
            elif line.startswith('[修复建议]:'):
                current_vuln['fix'] = line.split(':', 1)[1].strip()
                self.vulnerabilities.append(current_vuln)
                self.add_vuln_to_table(current_vuln)
                current_vuln = {}

    def add_vuln_to_table(self, vuln):
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        self.vuln_table.setItem(row, 0, QTableWidgetItem(os.path.basename(vuln.get('file', ''))))
        self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln.get('type', '')))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln.get('level', '')))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.get('location', '')))
        self.vuln_table.setItem(row, 4, QTableWidgetItem(vuln.get('detail', '')))
        self.vuln_table.setItem(row, 5, QTableWidgetItem(vuln.get('fix', '')))
        self.vuln_table.resizeColumnsToContents()

    def stop_processing(self):
        if hasattr(self, 'analysis_thread') and self.analysis_thread.isRunning():
            self.analysis_thread.stop()
            self.status_bar.showMessage("处理已中止")
            self.progress.hide()
            self.status_label.hide()

    def extract_sensitive_info(self):
        self.reset_button_styles()
        self.extract_btn.setProperty("state", "active")
        self.extract_btn.style().polish(self.extract_btn)

        selected_files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        if not selected_files:
            QMessageBox.warning(self, "警告", "请选择要分析的文件！")
            return

        combined_result = ""
        for file_path in selected_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                self.extract_btn.setProperty("state", "error")
                self.extract_btn.style().polish(self.extract_btn)
                QTimer.singleShot(2000, self.reset_button_styles)
                QMessageBox.critical(self, "错误", f"读取文件失败: {str(e)}")
                return

            patterns = {
                "密码": r'(password|passwd|pwd)\s*=\s*[\'"](.*?)[\'"]',
                "API密钥": r'(api_?key|access_?key)\s*=\s*[\'"](.*?)[\'"]',
                "云安全凭证": r'(AKIA|ASIA)[A-Z0-9]{16}',
                "JWT令牌": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                "数据库连接": r'(mysql|postgresql)://[\w-]+:[\w-]+@[\w.-]+/[\w-]+'
            }

            result = f"\n🔍 {os.path.basename(file_path)} 敏感信息：\n"
            for desc, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    result += f"\n▸ {desc}：\n"
                    for match in matches[:3]:
                        result += f"  - {match[1] if isinstance(match, tuple) else match}\n"
                    if len(matches) > 3:
                        result += f"  - 以及另外 {len(matches) - 3} 个相似项...\n"

            combined_result += result

        self.result_area.setText(combined_result)
        self.highlight_sensitive_content(combined_result)
        self.extract_btn.setProperty("state", "completed")
        self.extract_btn.style().polish(self.extract_btn)
        QTimer.singleShot(1000, self.reset_button_styles)

    def highlight_sensitive_content(self, text):
        highlight_color = QColor(255, 0, 0, 50)
        self.result_area.moveCursor(QTextCursor.Start)
        cursor = self.result_area.textCursor()
        cursor.beginEditBlock()

        patterns = {
            "密码": r'(password|passwd|pwd)\s*=\s*[\'"](.*?)[\'"]',
            "API密钥": r'(api_?key|access_?key)\s*=\s*[\'"](.*?)[\'"]',
            "云安全凭证": r'(AKIA|ASIA)[A-Z0-9]{16}',
            "JWT令牌": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            "数据库连接": r'(mysql|postgresql)://[\w-]+:[\w-]+@[\w.-]+/[\w-]+'
        }

        for pattern in patterns.values():
            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.finditer(text)
            for match in matches:
                start = match.start()
                end = match.end()
                cursor.setPosition(start)
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, end - start)
                format = cursor.charFormat()
                format.setBackground(highlight_color)
                cursor.setCharFormat(format)

        cursor.endEditBlock()

    def highlight_keywords(self, text):
        keywords = ["漏洞", "风险", "建议", "危险", "警告", "高危", "中危", "低危"]
        highlight_format = self.result_area.textCursor().charFormat()
        highlight_format.setBackground(QColor(255, 255, 0, 50))

        cursor = self.result_area.textCursor()
        cursor.movePosition(QTextCursor.Start)
        cursor.beginEditBlock()

        for keyword in keywords:
            regex = re.compile(re.escape(keyword))
            matches = regex.finditer(text)
            for match in matches:
                start = match.start()
                end = match.end()
                cursor.setPosition(start)
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, end - start)
                cursor.mergeCharFormat(highlight_format)

        cursor.endEditBlock()

    def clear_cache(self):
        self.cache.clear()
        QMessageBox.information(self, "提示", "缓存已清空")

    def closeEvent(self, event):
        if hasattr(self, 'analysis_thread') and self.analysis_thread.isRunning():
            reply = QMessageBox.question(
                self, '后台任务',
                "分析仍在进行中，确定要退出吗？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.analysis_thread.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CodeAuditTool()
    window.show()
    sys.exit(app.exec_())