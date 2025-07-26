import ctypes
import os
import re
import sys
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Tuple, List

from PySide6.QtCore import Qt, QPoint, QTimer, QRegularExpression
from PySide6.QtWidgets import (
  QApplication,
  QMainWindow,
  QWidget,
  QVBoxLayout,
  QHBoxLayout,
  QPushButton,
  QTabWidget,
  QFrame,
  QFileDialog,
  QMenu,
  QLabel,
  QDialog,
  QFormLayout,
  QLineEdit,
  QTextEdit,
  QDialogButtonBox,
  QMessageBox,
  QGroupBox,
  QScrollArea,
  QSpacerItem,
  QSystemTrayIcon,
  QStyle,
  QSizePolicy
)
from PySide6.QtGui import (
  QIcon,
  QResizeEvent,
  QPainter,
  QColor,
  QPaintEvent,
  QCloseEvent,
  QMouseEvent,
  QTextCharFormat,
  QSyntaxHighlighter,
  QFont
)


class Config:
  _local_mode = os.getenv("LOCAL") == "ON"

  @classmethod
  def get_icons(cls) -> Tuple[str, str]:
    if cls._local_mode:
      return (
        "resources/icons/active.png",
        "resources/icons/default.png"
      )
    else:
      return (
        "/opt/wirewizard/resources/icons/active.png",
        "/opt/wirewizard/resources/icons/default.png"
      )

  @classmethod
  def get_lib(cls) -> Path:
    if cls._local_mode: return Path(__file__).parent / "wirewizard.so"
    else: return Path("/opt/wirewizard/lib/wirewizard.so")

  @classmethod
  def get_folders(cls) -> List[str]:
    return ["/etc/wireguard", "/usr/local/etc/wireguard"]

  @classmethod
  def get_paths(cls, tunnel_name: str) -> List[str]:
    return [f"{folder}/{tunnel_name}.conf" for folder in cls.get_folders()]

class Wireguard:
  def __init__(self):
    lib = Config.get_lib()
    if not lib.exists():
      raise FileNotFoundError(f"WireGuard library not found at {lib}")

    self.wg = ctypes.CDLL(str(lib))

    class InterfacesNameResponse(ctypes.Structure):
      _fields_ = [
        ("Names", ctypes.POINTER(ctypes.c_char_p)),
        ("Count", ctypes.c_int)
      ]

    class ConfigResponse(ctypes.Structure):
      _fields_ = [
        ("InterfacePrivKey", ctypes.c_char_p),
        ("InterfacePubKey", ctypes.c_char_p),
        ("InterfaceListenPort", ctypes.c_int),
        ("InterfaceAddress", ctypes.c_char_p),
        ("InterfaceDNS", ctypes.c_char_p),
        ("PeerPubKey", ctypes.c_char_p),
        ("PeerEndpointAddress", ctypes.c_char_p),
        ("PeerAllowedIPs", ctypes.c_char_p),
        ("PeerPersistentKeepalive", ctypes.c_char_p)
      ]

    class StatsResponse(ctypes.Structure):
      _fields_ = [
        ("LastHandshakeTime", ctypes.c_char_p),
        ("Transfer", ctypes.c_char_p)
      ]

    self.wg.generateKeys.argtypes = [
      ctypes.POINTER(ctypes.c_char_p),
      ctypes.POINTER(ctypes.c_char_p)
    ]
    self.wg.generateKeys.restype = ctypes.c_char_p

    self.wg.readInterfacesName.restype = ctypes.POINTER(InterfacesNameResponse)
    self.wg.readInterfacesName.argtypes = []

    self.wg.readConfig.restype = ctypes.POINTER(ConfigResponse)
    self.wg.readConfig.argtypes = [ctypes.c_char_p]

    self.wg.readStats.restype = ctypes.POINTER(StatsResponse)
    self.wg.readStats.argtypes = [ctypes.c_char_p]

    self.wg.freeString.restype = None
    self.wg.freeString.argtypes = [ctypes.c_char_p]

    self.wg.freeInterfacesName.restype = None
    self.wg.freeInterfacesName.argtypes = [ctypes.POINTER(InterfacesNameResponse)]

    self.wg.freeConfig.restype = None
    self.wg.freeConfig.argtypes = [ctypes.POINTER(ConfigResponse)]

    self.wg.freeStats.restype = None
    self.wg.freeStats.argtypes = [ctypes.POINTER(StatsResponse)]

  def generate_keys(self) -> Tuple[str, str]:
    priv_key = ctypes.c_char_p()
    pub_key = ctypes.c_char_p()

    err = self.wg.generateKeys(ctypes.byref(priv_key), ctypes.byref(pub_key))
    if err:
      self.wg.freeString(err)
      return ("", "")

    result = (priv_key.value.decode("utf-8"), pub_key.value.decode("utf-8"))

    self.wg.freeString(priv_key)
    self.wg.freeString(pub_key)

    return result

  def read_interfaces_name(self) -> List[str]:
    interfaces_ptr = self.wg.readInterfacesName()
    if not interfaces_ptr: return []

    names = []
    interfaces = interfaces_ptr.contents

    try:
      for i in range(interfaces.Count):
        name = interfaces.Names[i].decode("utf-8")
        names.append(name)
    finally:
      self.wg.freeInterfacesName(interfaces_ptr)

    return names

  def read_config(self, interface: str) -> dict:
    cfg_ptr = self.wg.readConfig(interface.encode("utf-8"))
    if not cfg_ptr: return {}

    cfg = cfg_ptr.contents

    try:
      return {
        "interface_priv_key": self._str_decode(cfg.InterfacePrivKey),
        "interface_pub_key": self._str_decode(cfg.InterfacePubKey),
        "interface_listen_port": cfg.InterfaceListenPort,
        "interface_address": self._str_decode(cfg.InterfaceAddress),
        "interface_dns": self._str_decode(cfg.InterfaceDNS),
        "peer_pub_key": self._str_decode(cfg.PeerPubKey),
        "peer_endpoint_address": self._str_decode(cfg.PeerEndpointAddress),
        "peer_allowed_ips": self._str_decode(cfg.PeerAllowedIPs),
        "peer_keep_alive": self._str_decode(cfg.PeerPersistentKeepalive)
      }
    finally:
      self.wg.freeConfig(cfg_ptr)

  def read_stats(self, interface: str) -> dict:
    cfg_ptr = self.wg.readStats(interface.encode("utf-8"))
    if not cfg_ptr: return {}

    cfg = cfg_ptr.contents

    try:
      return {
        "last_handshake": self._str_decode(cfg.LastHandshakeTime),
        "transfer": self._str_decode(cfg.Transfer)
      }
    finally:
      self.wg.freeStats(cfg_ptr)

  def _str_decode(self, c_str: ctypes.c_char_p) -> str:
    return c_str.decode("utf-8") if c_str else ""

class WireGuardHighlighter(QSyntaxHighlighter):
  def __init__(self, parent=None):
    super().__init__(parent)

    self.section_format = QTextCharFormat()
    self.section_format.setForeground(QColor("#2e6a77"))

    self.key_format = QTextCharFormat()
    self.key_format.setForeground(QColor("#9945a1"))
    self.key_format.setFontWeight(QFont.Bold)

    self.value_format = QTextCharFormat()
    self.value_format.setForeground(QColor("#2324df"))

    self.special_value_format = QTextCharFormat()
    self.special_value_format.setForeground(QColor("#64492d"))

    self.section_pattern = QRegularExpression(r"^\s*\[(Interface|Peer)\]\s*$")
    self.key_value_pattern = QRegularExpression(r"^\s*([A-Za-z]+)\s*=\s*(.+)$")
    octet = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    self.ip_pattern = QRegularExpression(
      r"(" + octet + r"\." + octet + r"\." + octet + r"\." + octet + r")([:/]\d+)(?:,|\s|$)?"
    )

  def highlightBlock(self, text: str) -> None:
    section_match = self.section_pattern.match(text)
    if section_match.hasMatch():
      self.setFormat(
        section_match.capturedStart(0),
        section_match.capturedLength(0),
        self.section_format
      )
      return

    key_value_match = self.key_value_pattern.match(text)
    if key_value_match.hasMatch():
      self.setFormat(
        key_value_match.capturedStart(1),
        key_value_match.capturedLength(1),
        self.key_format
      )

      if key_value_match.captured(1) in ["PrivateKey", "PublicKey"]:
        self.setFormat(
          key_value_match.capturedStart(2),
          key_value_match.capturedLength(2),
          self.special_value_format
        )
      else:
        self.setFormat(
          key_value_match.capturedStart(2),
          key_value_match.capturedLength(2),
          self.value_format
        )

        ip_match_iterator = self.ip_pattern.globalMatch(
          key_value_match.captured(2).strip()
        )
        while ip_match_iterator.hasNext():
          ip_match = ip_match_iterator.next()

          self.setFormat(
            key_value_match.capturedStart(2) + ip_match.capturedStart(1),
            ip_match.capturedStart(1),
            self.value_format
          )
          self.setFormat(
            key_value_match.capturedStart(2) + ip_match.capturedStart(2),
            ip_match.capturedLength(2),
            self.special_value_format
          )

class TunnelCreationDialog(QDialog):
  def __init__(self, wireguard: Wireguard, parent=None):
    super().__init__(parent)
    self.setWindowTitle("Create new tunnel")
    self.setFixedSize(500, 400)

    self.wireguard = wireguard

    self.name_input = None
    self.config_dir = None
    self.highlighter = None

    self.init_ui()

  def init_ui(self) -> None:
    layout = QVBoxLayout()
    form_layout = QFormLayout()

    priv_key, pub_key = self.wireguard.generate_keys()

    self.name_input = QLineEdit()
    public_key = QLineEdit()
    public_key.setText(pub_key)
    form_layout.addRow("Name:", self.name_input)
    form_layout.addRow("Public Key:", public_key)

    self.text_edit = QTextEdit()
    self.text_edit.setFontFamily("Monospace")
    self.text_edit.setFontPointSize(10)
    self.text_edit.setPlainText("[Interface]" + "\n" + f"PrivateKey = {priv_key}")

    self.highlighter = WireGuardHighlighter(self.text_edit)

    button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
    button_box.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #dae7ed;
      }
      """
    )
    button_box.accepted.connect(self.save_config)
    button_box.rejected.connect(self.reject)

    layout.addLayout(form_layout)
    layout.addWidget(self.text_edit)
    layout.addWidget(button_box)

    self.setLayout(layout)

  def save_config(self) -> None:
    name = self.name_input.text().strip()
    if not self.validate_config(name): return

    try:
      with open(
        os.path.join(self.config_dir, f"{name}.conf"), "w", encoding="utf-8"
      ) as f:
        f.write(self.text_edit.toPlainText())

        self.accept()
    except Exception as e:
      QMessageBox.warning(
        self,
        "Error",
        f"Failed to save configuration file: {str(e)}"
      )

  def validate_config(self, name: str) -> bool:
    if not name:
      QMessageBox.warning(self, "Error", "Tunnel name cannot be empty.")
      return False

    """
    NOTE: (heycatch) interface naming rules are present in man8.
    Link: https://www.man7.org/linux/man-pages/man8/wg-quick.8.html
    """
    if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_=+.-]{1,15}[a-zA-Z0-9])?$", name):
      QMessageBox.warning(
        self,
        "Error",
        "Incorrect name for the tunnel is entered."
      )
      return False

    for folder in Config.get_folders():
      if os.path.isdir(folder):
        self.config_dir = folder
        break

    if not self.config_dir:
      QMessageBox.warning(self, "Error", "Configuration dirs do not exist.")
      return False

    if not os.access(self.config_dir, os.W_OK):
      QMessageBox.warning(
        self,
        "Error",
        f"No write permission for {self.config_dir}."
      )
      return False

    if os.path.isfile(os.path.join(self.config_dir, f"{name}.conf")):
      QMessageBox.warning(
        self,
        "Error",
        f"Configuration file for {name} already exists."
      )
      return False

    return True

class TunnelEditDialog(QDialog):
  def __init__(
    self,
    tunnel_name: str,
    wireguard: Wireguard,
    append_log: callable,
    parent=None
  ):
    super().__init__(parent)
    self.setWindowTitle("Edit tunnel")
    self.setFixedSize(500, 400)

    self.tunnel_name = tunnel_name
    self.wireguard = wireguard
    self.append_log = append_log

    self.config_file = None
    self.config_dir = None
    self.name_input = None
    self.highlighter = None

    self.init_ui()

  def init_ui(self) -> None:
    layout = QVBoxLayout()
    form_layout = QFormLayout()

    self.name_input = QLineEdit()
    self.name_input.setText(self.tunnel_name)
    form_layout.addRow("Name:", self.name_input)

    self.text_edit = QTextEdit()
    self.text_edit.setFontFamily("Monospace")
    self.text_edit.setFontPointSize(10)

    self.highlighter = WireGuardHighlighter(self.text_edit)

    layout.addLayout(form_layout)
    layout.addWidget(self.text_edit)

    button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
    button_box.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #dae7ed;
      }
      """
    )
    button_box.accepted.connect(self.save_config)
    button_box.rejected.connect(self.reject)
    layout.addWidget(button_box)

    self.setLayout(layout)

    self.load_config()

  def load_config(self) -> None:
    for path in Config.get_paths(self.tunnel_name):
      if os.path.isfile(path):
        self.config_file = path
        break

    if not self.config_file:
      QMessageBox.warning(
        self,
        "Error",
        f"Configuration file for {self.tunnel_name} not found.",
      )
      self.reject()
      return

    try:
      with open(self.config_file, "r", encoding="utf-8") as f:
        self.text_edit.setPlainText(f.read())
    except Exception as e:
      QMessageBox.warning(
        self,
        "Error",
        f"Failed to read configuration file to save: {str(e)}"
      )
      self.reject()

  def save_config(self) -> None:
    new_name = self.name_input.text().strip()
    if not self.validate_config(new_name): return

    try:
      if new_name != self.tunnel_name:
        config = self.wireguard.read_config(self.tunnel_name)
        if config.get("interface_listen_port", 0) != 0:
          try:
            cmd = ["wg-quick", "down", self.tunnel_name]
            res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
            self.append_log(cmd, res.stdout, res.stderr)
          except subprocess.CalledProcessError as e:
            self.append_log(cmd, e.stdout, e.stderr)
            QMessageBox.warning(
              self,
              "Error",
              f"Failed to stop tunnel {self.tunnel_name}."
            )
            return

        new_config_path = os.path.join(self.config_dir, f"{new_name}.conf")
        os.rename(self.config_file, new_config_path)
        self.config_file = new_config_path

      with open(self.config_file, "w", encoding="utf-8") as f:
        f.write(self.text_edit.toPlainText())

      self.accept()
    except Exception as e:
      QMessageBox.warning(
        self,
        "Error",
        f"Failed to save configuration file: {str(e)}"
      )
      self.reject()

  def validate_config(self, name: str) -> bool:
    if not name:
      QMessageBox.warning(self, "Error", "Tunnel name cannot be empty.")
      return False

    """
    NOTE: (heycatch) interface naming rules are present in man8.
    Link: https://www.man7.org/linux/man-pages/man8/wg-quick.8.html
    """
    if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_=+.-]{1,15}[a-zA-Z0-9])?$", name):
      QMessageBox.warning(
        self,
        "Error",
        "Incorrect name for the tunnel is entered."
      )
      return False

    for folder in Config.get_folders():
      if os.path.isdir(folder):
        self.config_dir = folder
        break

    if not self.config_dir:
      QMessageBox.warning(self, "Error", "Configuration dirs do not exist.")
      return False

    if not os.access(self.config_dir, os.W_OK):
      QMessageBox.warning(
        self,
        "Error",
        f"No write permission for {self.config_dir}."
      )
      return False

    if name != self.tunnel_name and os.path.isfile(
      os.path.join(self.config_dir, f"{name}.conf")
    ):
      QMessageBox.warning(
        self,
        "Error",
        f"Configuration file for {name} already exists."
      )
      return False

    return True

class TunnelButton(QPushButton):
  def __init__(self, name: str, is_active: bool = False, parent=None):
    super().__init__(name, parent)
    self.is_active = is_active

    self.is_selected = False

    self.update_style()

  def update_style(self) -> None:
    background = "#dae7ed" if self.is_selected else "transparent"

    self.setStyleSheet(
      f"""
      QPushButton {{
        background: {background};
        border: none;
        text-align: left;
        padding: 4px 4px 4px 18px;
        font-size: 13px;
      }}
      QPushButton:hover {{
        background: #dae7ed;
      }}
      """
    )

  def paintEvent(self, event: QPaintEvent) -> None:
    super().paintEvent(event)

    painter = QPainter(self)
    painter.setRenderHint(QPainter.Antialiasing)

    painter.setBrush(QColor("#4CAF50" if self.is_active else "#808080"))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(5, 9, 9, 9)

  def set_selected(self, selected: bool) -> None:
    self.is_selected = selected

    self.update_style()

  def mousePressEvent(self, event: QMouseEvent) -> None:
    if event.button() == Qt.LeftButton and event.modifiers() & Qt.ControlModifier:
      main_window = self.window()
      if isinstance(main_window, MainWindow):
        tunnel_name = self.text()
        if tunnel_name in main_window.selected_tunnels:
          main_window.selected_tunnels.remove(tunnel_name)
          self.set_selected(False)
          main_window.clear_right_panel()
        else:
          main_window.selected_tunnels.append(tunnel_name)
          self.set_selected(True)
    else:
      super().mousePressEvent(event)

class TunnelConfigWidget(QWidget):
  def __init__(
    self,
    name: str,
    config: dict,
    stats: dict,
    wireguard: Wireguard,
    is_active: bool = False,
    parent=None
  ):
    super().__init__(parent)
    self.layout = QVBoxLayout()
    self.layout.setContentsMargins(0, 0, 0, 0)

    self.name = name
    self.wireguard = wireguard
    self.is_active = is_active

    self.field_widget = {}

    group_style = """
      QGroupBox {
        border: 1px solid #ada9aa;
        margin-top: 10px;
        font-size: 12px;
      }
      QGroupBox:title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
      }
    """

    interface_group = QGroupBox(f"Interface: {name}")
    interface_group.setStyleSheet(group_style)
    interface_layout = QVBoxLayout()
    interface_layout.setContentsMargins(10, 10, 10, 10)
    interface_layout.setSpacing(5)

    inteface_fields = [
      ("Public key:  ", config.get("interface_pub_key", "")),
      ("Listen port:  ", str(
        config.get(
          "interface_listen_port"
        )) if config.get("interface_listen_port", 0) else ""),
      ("Addresses:  ", config.get("interface_address", "")),
      ("DNS servers:  ", config.get("interface_dns", ""))
    ]

    interface_label_width = []
    for label_text, value in inteface_fields:
      if value: interface_label_width.append(self.fontMetrics().horizontalAdvance(label_text))
    interface_max_width = max(interface_label_width)
    interface_max_length = max(len(field[0]) if field[1] else 0 for field in inteface_fields)

    status_layout = QHBoxLayout()
    status_label = QLabel("Status:  ")
    status_label.setFixedWidth(interface_max_width)
    status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    status_label.setFixedHeight(20)
    self.status_indicator = QLabel()
    self.status_indicator.setFixedSize(11, 11)
    self.status_indicator.setStyleSheet(
      f"background-color: {'#4CAF50' if is_active else '#808080'}; border-radius: 5px;"
    )
    status_text = QLabel("Active" if is_active else "Inactive")
    status_layout.addWidget(status_label)
    status_layout.addWidget(self.status_indicator)
    status_layout.addWidget(status_text)
    status_layout.addStretch()
    interface_layout.addLayout(status_layout)

    for label_text, value in inteface_fields:
      if not value: continue

      field_layout = QHBoxLayout()
      label = QLabel(label_text)
      label.setFixedWidth(interface_max_width)
      label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)

      value_edit = QTextEdit(value)
      value_edit.setReadOnly(True)
      value_edit.setFrameStyle(QFrame.NoFrame)
      value_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
      value_edit.setAlignment(Qt.AlignmentFlag.AlignTop)
      """
      NOTE: (heycatch) we use QTextEdit for convenient line wrapping,
      but it has an internal frame that needs to be removed for correct
      display. To do this, we we use 'document().setDocumentMargin(0)' and
      a fixed length in 'setMaximumHeight' for normal bottom maring.
      TODO: (heycatch) find a more dynamic and
      convenient way besides 'setMaximumHeight'.
      """
      value_edit.document().setDocumentMargin(0)
      if is_active and (len(value) >= 44 and interface_max_length >= 19) or len(value) >= 63:
        value_edit.setMaximumHeight(30)
      else:
        value_edit.setMaximumHeight(20)
      value_edit.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
      value_edit.setStyleSheet("background-color: #fbfbfb;")

      field_layout.addWidget(label)
      field_layout.addWidget(value_edit)
      interface_layout.addLayout(field_layout)

    button_layout = QHBoxLayout()
    button_layout.addSpacerItem(QSpacerItem(interface_max_width + 5, 0))
    self.active_button = QPushButton("Activate" if not is_active else "Deactivate")
    self.active_button.setFixedSize(100, 25)
    self.active_button.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #dae7ed;
      }
      """
    )
    button_layout.addWidget(self.active_button)
    button_layout.addStretch()
    interface_layout.addLayout(button_layout)
    interface_group.setLayout(interface_layout)

    peer_group = QGroupBox("Peer")
    peer_group.setStyleSheet(group_style)
    peer_layout = QVBoxLayout()
    peer_layout.setContentsMargins(10, 10, 10, 10)
    peer_layout.setSpacing(5)

    peer_fields = [
      ("Public key:  ", config.get("peer_pub_key", "")),
      # TODO: (heycatch) add support "Preshared key".
      ("Allowed IPs:  ", config.get("peer_allowed_ips", "")),
      ("Endpoint:  ", config.get("peer_endpoint_address", "")),
      ("Persistent keepalive:  ", config.get("peer_keep_alive", "")),
      ("Latest handshake:  ", stats.get("last_handshake", "")),
      ("Transfer:  ", stats.get("transfer", ""))
    ]

    peer_label_widths = []
    for label_text, value in peer_fields:
      if value: peer_label_widths.append(self.fontMetrics().horizontalAdvance(label_text))
    peer_max_width = max(peer_label_widths)
    peer_max_length = max(len(field[0]) if field[1] else 0 for field in peer_fields)

    for label_text, value in peer_fields:
      if not value: continue

      field_layout = QHBoxLayout()
      label = QLabel(label_text)
      label.setFixedWidth(peer_max_width)
      label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)

      value_edit = QTextEdit(value)
      value_edit.setReadOnly(True)
      value_edit.setFrameStyle(QFrame.NoFrame)
      value_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
      value_edit.setAlignment(Qt.AlignmentFlag.AlignTop)
      """
      NOTE: (heycatch) we use QTextEdit for convenient line wrapping,
      but it has an internal frame that needs to be removed for correct
      display. To do this, we we use 'document().setDocumentMargin(0)' and
      a fixed length in 'setMaximumHeight' for normal bottom maring.
      TODO: (heycatch) find a more dynamic and
      convenient way besides 'setMaximumHeight'.
      """
      value_edit.document().setDocumentMargin(0)
      if is_active and (len(value) >= 44 and peer_max_length >= 19) or len(value) >= 63:
        value_edit.setMaximumHeight(30)
      else:
        value_edit.setMaximumHeight(20)
      value_edit.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
      value_edit.setStyleSheet("background-color: #fbfbfb;")

      field_layout.addWidget(label)
      field_layout.addWidget(value_edit)

      if label_text in ("Latest handshake:  ", "Transfer:  "):
        self.field_widget[label_text] = value_edit

      peer_layout.addLayout(field_layout)

    peer_group.setLayout(peer_layout)

    self.layout.addWidget(interface_group)
    self.layout.addWidget(peer_group)
    self.layout.addStretch()
    self.setLayout(self.layout)

    self.update_timer = QTimer(self)
    self.update_timer.setInterval(60000)
    self.update_timer.timeout.connect(self.update_stats)
    if self.is_active: self.update_timer.start()

  def update_stats(self) -> None:
    if not self.is_active:
      self.update_timer.stop()
      return

    stats = self.wireguard.read_stats(self.name)
    if stats:
      if "Latest handshake:  " in self.field_widget:
        self.field_widget["Latest handshake:  "].setText(stats.get("last_handshake", ""))
      if "Transfer:  " in self.field_widget:
        self.field_widget["Transfer:  "].setText(stats.get("transfer", ""))

class MainWindow(QMainWindow):
  def __init__(self):
    super().__init__()
    self.active_icon, self.default_icon = Config.get_icons()

    self.setWindowTitle("WireGuard")
    self.setWindowIcon(QIcon(self.default_icon))
    self.setFixedSize(750, 550)

    self.wireguard = Wireguard()

    self.logs = ""
    self.edit_button = None
    self.selected_tunnel = None
    self.selected_button = None
    self.selected_tunnels = []

    self.tray_icon = QSystemTrayIcon(self)
    self.tray_icon.setIcon(QIcon(self.default_icon))
    tray_menu = QMenu()
    open_acton = tray_menu.addAction("Show")
    open_acton.triggered.connect(self.showNormal)
    exit_action = tray_menu.addAction("Exit")
    exit_action.triggered.connect(self.quit_application)
    self.tray_icon.setContextMenu(tray_menu)
    self.tray_icon.activated.connect(self.tray_icon_activated)
    self.tray_icon.show()

    central_widget = QWidget()
    central_layout = QVBoxLayout()
    central_layout.setContentsMargins(5, 5, 5, 5)
    self.tabs = QTabWidget()
    central_layout.addWidget(self.tabs)
    central_widget.setLayout(central_layout)
    self.setCentralWidget(central_widget)

    self.tunnels_tab = QWidget()
    self.tabs.addTab(self.tunnels_tab, "Tunnels")
    self.setup_tunnels_tab()

    self.logs_tab = QWidget()
    self.tabs.addTab(self.logs_tab, "Logs")
    self.setup_logs_tab()

    self.tabs.setCurrentIndex(0)

    self.load_interfaces()

  def setup_tunnels_tab(self) -> None:
    main_layout = QVBoxLayout()
    content_layout = QHBoxLayout()

    self.left_panel = QFrame()
    self.left_panel.setFrameShape(QFrame.Box)
    self.left_panel.setLineWidth(1)
    self.left_panel.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    self.left_panel.customContextMenuRequested.connect(
      lambda pos: self.show_context_menu(pos, from_button=False, sender=self.left_panel)
    )

    self.left_widget = QWidget()
    self.left_layout = QVBoxLayout()
    self.left_layout.setContentsMargins(0, 0, 0, 0)
    self.left_layout.setSpacing(0)
    self.left_layout.addStretch()
    self.left_widget.setLayout(self.left_layout)

    scroll_area = QScrollArea()
    scroll_area.setWidget(self.left_widget)
    scroll_area.setWidgetResizable(True)
    scroll_area.setStyleSheet("border: none;")
    scroll_area.setContentsMargins(0, 0, 0, 0)

    left_panel_layout = QVBoxLayout()
    left_panel_layout.setContentsMargins(0, 0, 0, 0)
    left_panel_layout.addWidget(scroll_area)
    self.left_panel.setLayout(left_panel_layout)

    self.right_panel = QWidget()
    self.right_layout = QVBoxLayout()
    self.right_layout.setContentsMargins(0, 0, 0, 0)
    import_btn = QPushButton("Import tunnel(s) from file")
    import_btn.setStyleSheet("font-weight: bold; font-size: 15px;")
    import_btn.clicked.connect(self.import_tunnels)
    self.right_layout.addStretch()
    self.right_layout.addWidget(import_btn, alignment=Qt.AlignmentFlag.AlignCenter)
    self.right_layout.addStretch()
    self.right_panel.setLayout(self.right_layout)

    content_layout.addWidget(self.left_panel)
    content_layout.addWidget(self.right_panel)
    content_layout.setStretch(0, 1)
    content_layout.setStretch(1, 2)

    self.bottom_layout = QHBoxLayout()
    self.button_panel = QWidget()
    self.button_panel.setStyleSheet("QPushButton:hover { background: #dae7ed; }")
    self.buttons_layout = QHBoxLayout()
    self.buttons_layout.setContentsMargins(0, 0, 0, 0)

    # NOTE: (heycatch) indentation left at the beginning on purpose.
    add_tunnel_btn = QPushButton(" Add Tunnel")
    add_tunnel_btn.setIcon(self.style().standardIcon(QStyle.SP_DriveNetIcon))
    add_tunnel_btn.setFixedSize(110, 25)
    add_tunnel_menu = QMenu(self)
    import_action = add_tunnel_menu.addAction("Import tunnel(s) from file...")
    import_action.triggered.connect(self.import_tunnels)
    add_action = add_tunnel_menu.addAction("Add empty tunnel...")
    add_action.triggered.connect(self.create_tunnel)
    add_tunnel_btn.setMenu(add_tunnel_menu)
    add_tunnel_btn.setStyleSheet(
      """
      QPushButton::menu-indicator {
        subcontrol-origin: padding;
        subcontrol-position: right center;
        width: 10px;
        height: 10px;
        margin-right: 2px;
      }
      """
    )
    self.buttons_layout.addWidget(add_tunnel_btn)

    separator_one = QFrame()
    separator_one.setFrameShape(QFrame.VLine)
    separator_one.setFrameShadow(QFrame.Sunken)
    separator_one.setFixedSize(8, 25)
    self.buttons_layout.addWidget(separator_one)

    delete_btn = QPushButton()
    delete_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
    delete_btn.setFixedSize(50, 25)
    delete_btn.setToolTip("Remove selected tunnel(s)...")
    delete_btn.clicked.connect(self.remove_tunnel)
    self.buttons_layout.addWidget(delete_btn)

    separator_two = QFrame()
    separator_two.setFrameShape(QFrame.VLine)
    separator_two.setFrameShadow(QFrame.Sunken)
    separator_two.setFixedSize(8, 25)
    self.buttons_layout.addWidget(separator_two)

    export_btn = QPushButton()
    export_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
    export_btn.setFixedSize(50, 25)
    export_btn.setToolTip("Export all tunnels to zip...")
    export_btn.clicked.connect(self.export_tunnels)
    self.buttons_layout.addWidget(export_btn)

    self.button_panel.setLayout(self.buttons_layout)
    self.bottom_layout.addWidget(self.button_panel)
    self.bottom_layout.addStretch()

    main_layout.addLayout(content_layout, 1)
    main_layout.addLayout(self.bottom_layout)

    self.tunnels_tab.setLayout(main_layout)

  def setup_logs_tab(self) -> None:
    layout = QVBoxLayout()

    log_frame = QFrame()
    log_frame.setLineWidth(1)

    log_layout = QVBoxLayout()
    log_layout.setContentsMargins(0, 0, 0, 0)

    self.logs_text = QTextEdit()
    self.logs_text.setReadOnly(True)
    self.logs_text.setFontFamily("Monospace")
    self.logs_text.setFontPointSize(10)
    self.logs_text.setPlainText(self.logs)
    log_layout.addWidget(self.logs_text)

    log_frame.setLayout(log_layout)
    layout.addWidget(log_frame)

    button_layout = QHBoxLayout()
    button_layout.addStretch()
    save_button = QPushButton("Save")
    save_button.setFixedSize(100, 25)
    save_button.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #dae7ed;
      }
      """
    )
    save_button.clicked.connect(self.save_logs)
    button_layout.addWidget(save_button)

    layout.addLayout(button_layout)

    self.logs_tab.setLayout(layout)

  def save_logs(self) -> None:
    if not self.logs:
      QMessageBox.warning(self, "Error", "The logs are empty.")
      return

    file_dialog = QFileDialog(self)
    file_dialog.setAcceptMode(QFileDialog.AcceptSave)
    file_dialog.setNameFilter("Log files (*.log)")
    file_dialog.setDefaultSuffix("log")
    file_dialog.selectFile("wireguard-linux.log")

    if file_dialog.exec():
      file_path = file_dialog.selectedFiles()[0]
      try:
        with open(file_path, "w", encoding="utf-8") as f:
          f.write(self.logs)

        QMessageBox.information(
          self,
          "Success",
          f"The logs have been saved in {file_path}."
        )
      except Exception as e:
        QMessageBox.warning(self, "Error", f"Couldn't save logs: {str(e)}")

  def closeEvent(self, event: QCloseEvent) -> None:
    event.ignore()
    self.hide()

    super().closeEvent(event)

  def resizeEvent(self, event: QResizeEvent) -> None:
    self.left_panel.setFixedWidth(self.width() // 3)
    self.button_panel.setMaximumWidth(self.width() // 3)

    super().resizeEvent(event)

  def set_icon(self) -> None:
    is_active = False
    for interface in self.wireguard.read_interfaces_name():
      config = self.wireguard.read_config(interface)
      if config.get("interface_listen_port", 0) != 0:
        is_active = True
        break

    self.setWindowIcon(QIcon(
      self.active_icon if is_active else self.default_icon
    ))
    self.tray_icon.setIcon(QIcon(
      self.active_icon if is_active else self.default_icon
    ))

  def tray_icon_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
    if reason == QSystemTrayIcon.Trigger: self.showNormal()

  def quit_application(self) -> None:
    for interface in self.wireguard.read_interfaces_name():
      config = self.wireguard.read_config(interface)
      if config.get("interface_listen_port", 0) != 0:
        try:
          subprocess.run(["wg-quick", "down", interface], check=True)
        except subprocess.CalledProcessError:
          QMessageBox.warning(self, "Error", f"Failed to stop tunnel {interface}.")

    QApplication.quit()

  def load_interfaces(self) -> None:
    if hasattr(self, "left_panel"): self.left_widget.deleteLater()

    self.left_widget = QWidget()
    self.left_layout = QVBoxLayout()
    self.left_layout.setContentsMargins(0, 0, 0, 0)
    self.left_layout.setSpacing(0)
    self.left_widget.setLayout(self.left_layout)

    scroll_area = self.left_panel.findChild(QScrollArea)
    scroll_area.setWidget(self.left_widget)

    for name in self.wireguard.read_interfaces_name():
      config = self.wireguard.read_config(name)

      button = TunnelButton(
        name, is_active=config.get("interface_listen_port", 0) != 0
      )
      button.clicked.connect(lambda _, n=name: self.show_tunnel(n))
      button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
      button.customContextMenuRequested.connect(
        lambda pos, n=name, b=button: self.show_context_menu(
          pos, from_button=True, tunnel_name=n, sender=b
        )
      )
      self.left_layout.addWidget(button)

    self.set_icon()

    self.left_layout.addStretch()

  # NOTE: (heycatch) if logs exceed the 6MB limit, half of the old logs are cleaned up.
  def append_log(self, cmd: List[str], stdout: str, stderr: str) -> None:
    date = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
    self.logs += f"{date} {' '.join(cmd)}:\n{stdout}{stderr}\n"

    if len(self.logs) > 6000000: self.logs = self.logs[-6000000 // 2:]
    if hasattr(self, "logs_text"): self.logs_text.setPlainText(self.logs)

  def clear_right_panel(self) -> None:
    while self.right_layout.count():
      item = self.right_layout.takeAt(0)
      if item.widget(): item.widget().deleteLater()

    self.selected_tunnel = None
    self.selected_button = None

    if self.edit_button:
      self.bottom_layout.removeWidget(self.edit_button)
      self.edit_button.deleteLater()
      self.edit_button = None

    import_btn = QPushButton("Import tunnel(s) from file")
    import_btn.setStyleSheet("font-weight: bold; font-size: 15px;")
    import_btn.clicked.connect(self.import_tunnels)
    self.right_layout.addStretch()
    self.right_layout.addWidget(import_btn, alignment=Qt.AlignmentFlag.AlignCenter)
    self.right_layout.addStretch()
    self.right_panel.setLayout(self.right_layout)

  def show_context_menu(
    self,
    position: QPoint,
    from_button: bool = False,
    tunnel_name: str = None,
    sender: QWidget = None
  ) -> None:
    menu = QMenu(self)

    """
    NOTE: (heycatch) this condition is required when the tunnel is active
    in order to correctly press the "Activate/Deactivate" button.
    """
    if not from_button and not tunnel_name and self.selected_tunnel:
      tunnel_name = self.selected_tunnel

    self.selected_tunnel = tunnel_name

    len_interfaces = len(self.wireguard.read_interfaces_name())

    if from_button and tunnel_name:
      self.selected_tunnel = tunnel_name
      for i in range(self.left_layout.count()):
        widget = self.left_layout.itemAt(i).widget()
        if isinstance(widget, TunnelButton):
          widget.set_selected(
            widget.text() == tunnel_name or widget.text() in self.selected_tunnels
          )

      toggle_action = menu.addAction("Toggle")
      toggle_action.setEnabled(
        len_interfaces > 1 and self.selected_tunnel is not None
      )
      toggle_action.triggered.connect(self.toggle_tunnel)

      menu.addSeparator()

      import_action = menu.addAction("Import tunnel(s) from file...")
      import_action.setEnabled(False)
      add_action = menu.addAction("Add empty tunnel...")
      add_action.setEnabled(False)
      export_action = menu.addAction("Export all tunnels to zip...")
      export_action.setEnabled(False)

      menu.addSeparator()

      edit_action = menu.addAction("Edit selected tunnel...")
      edit_action.setEnabled(
        len_interfaces > 0 and self.selected_tunnel is not None
      )
      edit_action.triggered.connect(lambda: self.edit_tunnel())
      remove_action = menu.addAction("Remove selected tunnel(s)...")
      remove_action.setEnabled(
        len_interfaces > 0 and self.selected_tunnel is not None
      )
      remove_action.triggered.connect(self.remove_tunnel)

      select_all_action = menu.addAction("Select all")
      select_all_action.setEnabled(False)
    else:
      toggle_action = menu.addAction("Toggle")
      toggle_action.setEnabled(False)

      menu.addSeparator()

      menu.addAction("Import tunnel(s) from file...", self.import_tunnels)
      menu.addAction("Add empty tunnel...", self.create_tunnel)
      export_action = menu.addAction("Export all tunnels to zip...")
      export_action.setEnabled(len_interfaces > 0)
      export_action.triggered.connect(self.export_tunnels)

      menu.addSeparator()

      edit_action = menu.addAction("Edit selected tunnel...")
      edit_action.setEnabled(False)
      remove_action = menu.addAction("Remove selected tunnel(s)...")
      remove_action.setEnabled(False)

      if len(self.selected_tunnels) > 0:
        unselect_all_action = menu.addAction("Unselect all")
        unselect_all_action.triggered.connect(self.unselect_all_tunnels)
      else:
        select_all_action = menu.addAction("Select all")
        select_all_action.triggered.connect(self.selected_all_tunnels)

    if sender: menu.exec(sender.mapToGlobal(position))
    else: menu.exec(self.left_panel.mapToGlobal(position))

  def selected_all_tunnels(self) -> None:
    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()
      if isinstance(widget, TunnelButton):
        widget.set_selected(True)
        self.selected_tunnels.append(widget.text())

  def unselect_all_tunnels(self) -> None:
    self.selected_tunnels.clear()

    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()
      if isinstance(widget, TunnelButton):
        widget.set_selected(False)

    self.clear_right_panel()

  def create_tunnel(self) -> None:
    dialog = TunnelCreationDialog(self.wireguard, self)
    if dialog.exec() == QDialog.DialogCode.Accepted:
      self.load_interfaces()

  def show_tunnel(self, name: str) -> None:
    self.selected_tunnel = name
    self.selected_button = None

    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()
      if isinstance(widget, TunnelButton):
        widget.set_selected(
          widget.text() == name or widget.text() in self.selected_tunnels
        )
        if widget.text() == name: self.selected_button = widget

    while self.right_layout.count():
      item = self.right_layout.takeAt(0)
      if item.widget(): item.widget().deleteLater()

    if self.edit_button:
      self.bottom_layout.removeWidget(self.edit_button)
      self.edit_button.deleteLater()
      self.edit_button = None

    config = self.wireguard.read_config(name)
    stats = self.wireguard.read_stats(name)

    if len(config) == 0 and len(stats) == 0:
      QMessageBox.warning(self, "Error", "Failed to read the configuration file.")

      import_btn = QPushButton("Import tunnel(s) from file")
      import_btn.setStyleSheet("font-weight: bold; font-size: 15px;")
      import_btn.clicked.connect(self.import_tunnels)
      self.right_layout.addStretch()
      self.right_layout.addWidget(import_btn, alignment=Qt.AlignmentFlag.AlignCenter)
      self.right_layout.addStretch()
      self.right_panel.setLayout(self.right_layout)

      self.set_icon()

      return

    is_active = config.get("interface_listen_port", 0) != 0
    config_widget = TunnelConfigWidget(
      name, config, stats, self.wireguard, is_active=is_active
    )
    config_widget.active_button.clicked.connect(
      lambda: self.toggle_tunnel(is_active)
    )
    self.right_layout.addWidget(config_widget)

    self.edit_button = QPushButton("Edit")
    self.edit_button.setFixedSize(100, 25)
    self.edit_button.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #dae7ed;
      }
      """
    )
    self.edit_button.clicked.connect(lambda: self.edit_tunnel())
    self.bottom_layout.addWidget(self.edit_button)

  def edit_tunnel(self) -> None:
    tunnel_name = None

    for i in range(self.right_layout.count()):
      widget = self.right_layout.itemAt(i).widget()
      if isinstance(widget, TunnelConfigWidget):
        self.selected_tunnel = widget.name
        break

    if tunnel_name is None: tunnel_name = self.selected_tunnel

    if tunnel_name is None:
      QMessageBox.warning(self, "Error", "No tunnel selected.")
      return

    """
    NOTE: (heycatch) when you right-click with an active tunnel in right_panel,
    self.selected_tunnel is reset and we cannot change the configuration file.
    A check for the existence of right_panel has been added.
    self.selected_tunnel -> tunnel_name.
    """
    dialog = TunnelEditDialog(tunnel_name, self.wireguard, self.append_log, self)
    if dialog.exec() == QDialog.DialogCode.Accepted:
      self.load_interfaces()

      if dialog.name_input.text().strip() in self.wireguard.read_interfaces_name():
        self.show_tunnel(dialog.name_input.text().strip())
      else:
        self.show_tunnel(self.selected_tunnel)

  def toggle_tunnel(self, is_active: bool) -> None:
    if not self.selected_tunnel: return

    new_state = not is_active
    if new_state:
      active_tunnel = None
      for interface in self.wireguard.read_interfaces_name():
        config = self.wireguard.read_config(interface)
        if config.get("interface_listen_port", 0) != 0:
          active_tunnel = interface
          break

      if active_tunnel and active_tunnel != self.selected_tunnel:
        try:
          cmd = ["wg-quick", "down", active_tunnel]
          res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
          self.append_log(cmd, res.stdout, res.stderr)
        except subprocess.CalledProcessError as e:
          self.append_log(cmd, e.stdout, e.stderr)
          QMessageBox.warning(self, "Error", f"Failed to stop tunnel {active_tunnel}")
          return

    try:
      if new_state: cmd = ["wg-quick", "up", self.selected_tunnel]
      else: cmd = ["wg-quick", "down", self.selected_tunnel]
      res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
      self.append_log(cmd, res.stdout, res.stderr)
    except subprocess.CalledProcessError as e:
      self.append_log(cmd, e.stdout, e.stderr)
      """
      NOTE: (heycatch) in this place we do not need return,
      because we need to update the visual state of buttons and indicators.
      """
      QMessageBox.warning(self, "Error", "Failed to toggle tunnel.")

    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()
      if isinstance(widget, TunnelButton):
        config = self.wireguard.read_config(widget.text())
        widget.is_active = config.get("interface_listen_port", 0) != 0
        widget.update()

    self.set_icon()

    self.show_tunnel(self.selected_tunnel)

  def remove_tunnel(self) -> None:
    if not self.selected_tunnels and not self.selected_tunnel: return

    len_tunnels = len(self.selected_tunnels)
    if len_tunnels > 0:
      custom_message = f"Are you sure you want to remove {self.selected_tunnels} tunnels?"
    else:
      custom_message = f"Are you sure you want to remove tunnel {self.selected_tunnel}?"

    reply = QMessageBox.question(
      self,
      "Confirm",
      custom_message,
      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )

    if reply == QMessageBox.StandardButton.Yes:
      if len_tunnels > 0:
        for tunnel in self.selected_tunnels:
          check_tunnel = self.wireguard.read_config(tunnel)
          if check_tunnel.get("interface_listen_port", 0) != 0:
            try:
              cmd = ["wg-quick", "down", tunnel]
              res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
              self.append_log(cmd, res.stdout, res.stderr)
            except subprocess.CalledProcessError as e:
              self.append_log(cmd, e.stdout, e.stderr)
              QMessageBox.warning(self, "Error", f"Failed to stop tunnel {tunnel}.")
              continue

          for config in Config.get_folders():
            if not os.path.exists(config): continue

            path = os.path.join(config, f"{tunnel}.conf")
            if os.path.isfile(path):
              try:
                if not os.access(path, os.W_OK):
                  QMessageBox.warning(
                    self,
                    "Error",
                    f"No delete permission for {path}."
                  )
                  continue

                os.remove(path)
                break
              except Exception as e:
                QMessageBox.warning(
                  self,
                  "Error",
                  f"Failed to delete configuration file: {str(e)}"
                )
                continue

        for tunnel in self.selected_tunnels:
          for i in range(self.left_layout.count()):
            widget = self.left_layout.itemAt(i).widget()
            if isinstance(widget, TunnelButton) and widget.text() == tunnel:
              widget.deleteLater()
              break

        self.selected_tunnels.clear()
      else:
        for path in Config.get_paths(self.selected_tunnel):
          if os.path.isfile(path):
            try:
              check_tunnel = self.wireguard.read_config(self.selected_tunnel)
              if check_tunnel.get("interface_listen_port", 0) != 0:
                try:
                  cmd = ["wg-quick", "down", self.selected_tunnel]
                  res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=20)
                  self.append_log(cmd, res.stdout, res.stderr)
                except subprocess.CalledProcessError as e:
                  self.append_log(cmd, e.stdout, e.stderr)
                  QMessageBox.warning(
                    self,
                    "Error",
                    f"Failed to stop tunnel {self.selected_tunnel}."
                  )
                  break

              if not os.access(path, os.W_OK):
                QMessageBox.warning(
                  self,
                  "Error",
                  f"No delete permission for {path}."
                )
                break

              os.remove(path)
              break
            except Exception as e:
              QMessageBox.warning(
                self,
                "Error",
                f"Failed to delete configuration file: {str(e)}"
              )
              return

        for i in range(self.left_layout.count()):
          widget = self.left_layout.itemAt(i).widget()
          if isinstance(widget, TunnelButton) and widget.text() == self.selected_tunnel:
            widget.deleteLater()
            break

      self.clear_right_panel()

      self.load_interfaces()

  def import_tunnels(self) -> None:
    file_dialog = QFileDialog(self)
    file_dialog.setNameFilter("Config files (*.conf)")
    file_dialog.setFileMode(QFileDialog.ExistingFiles)

    if file_dialog.exec():
      config_dir = None
      count = 0

      for folder in Config.get_folders():
        if os.path.isdir(folder):
          config_dir = folder
          break

      if not config_dir:
        QMessageBox.warning(self, "Error", "Configuration dirs do not exist.")
        return

      if not os.access(config_dir, os.W_OK):
        QMessageBox.warning(
          self,
          "Error",
          f"No import permission for {config_dir}."
        )
        return

      files = file_dialog.selectedFiles()
      for file_path in files:
        try:
          file_name = os.path.basename(file_path)
          if not file_name.endswith(".conf"): continue

          dest_path = os.path.join(config_dir, file_name)
          if os.path.exists(dest_path):
            reply = QMessageBox.question(
              self,
              "File exists",
              f"File {file_name} already exists. Overwrite?",
              QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No: continue

          with open(file_path, "r", encoding="utf-8") as src_file:
            with open(dest_path, "w", encoding="utf-8") as dst_file:
              dst_file.write(src_file.read())

          count += 1
        except Exception as e:
          QMessageBox.warning(
            self,
            "Error",
            f"Failed to import file {file_name}: {str(e)}"
          )
          continue

      if count > 0:
        QMessageBox.information(
          self,
          "Success",
          f"Successfully imported {count} tunnel(s)."
        )

      self.load_interfaces()
    else:
      QMessageBox.warning(self, "Error", "No files were imported.")

  def export_tunnels(self) -> None:
    config_dir = None

    for folder in Config.get_folders():
      if os.path.isdir(folder):
        config_dir = folder
        break

    if not config_dir:
      QMessageBox.warning(self, "Error", "Configuration dirs do not exist.")
      return

    conf_files = [f for f in os.listdir(config_dir) if f.endswith(".conf")]
    if not conf_files:
      QMessageBox.warning(self, "Error", "Configuration files do not exist.")
      return

    file_dialog = QFileDialog(self)
    file_dialog.setAcceptMode(QFileDialog.AcceptSave)
    file_dialog.setNameFilter("ZIP archives (*.zip)")
    file_dialog.setDefaultSuffix("zip")
    file_dialog.selectFile("wireguard_configs.zip")

    if not file_dialog.exec(): return

    zip_path = file_dialog.selectedFiles()[0]

    try:
      with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for conf_file in conf_files:
          full_path = os.path.join(config_dir, conf_file)
          zipf.write(full_path, arcname=conf_file)

      QMessageBox.information(
        self,
        "Success",
        f"Successfully exported {len(conf_files)} configurations to:\n{zip_path}."
      )
    except Exception as e:
      QMessageBox.warning(
        self,
        "Error",
        f"Failed to creat ZIP archive: {str(e)}"
      )

if __name__ == "__main__":
  app = QApplication([])
  app.setApplicationName("WireGuard")
  app.setQuitOnLastWindowClosed(False)

  window = MainWindow()
  window.show()

  sys.exit(app.exec())
