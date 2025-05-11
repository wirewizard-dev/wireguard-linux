import ctypes
import os
import re
import sys
import subprocess
import zipfile
from pathlib import Path
from typing import Tuple, List

from PySide6.QtCore import Qt, QPoint, QTimer
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
  QSystemTrayIcon
)
from PySide6.QtGui import (
  QIcon,
  QResizeEvent,
  QPainter,
  QColor,
  QPaintEvent,
  QCloseEvent
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
        "interface_priv_key": cfg.InterfacePrivKey.decode("utf-8") if cfg.InterfacePrivKey else "",
        "interface_pub_key": cfg.InterfacePubKey.decode("utf-8") if cfg.InterfacePubKey else "",
        "interface_listen_port": cfg.InterfaceListenPort,
        "interface_address": cfg.InterfaceAddress.decode("utf-8") if cfg.InterfaceAddress else "",
        "interface_dns": cfg.InterfaceDNS.decode("utf-8") if cfg.InterfaceDNS else "",
        "peer_pub_key": cfg.PeerPubKey.decode("utf-8") if cfg.PeerPubKey else "",
        "peer_endpoint_address": cfg.PeerEndpointAddress.decode("utf-8") if cfg.PeerEndpointAddress else "",
        "peer_allowed_ips": cfg.PeerAllowedIPs.decode("utf-8") if cfg.PeerAllowedIPs else "",
        "peer_keep_alive": cfg.PeerPersistentKeepalive.decode("utf-8") if cfg.PeerPersistentKeepalive else ""
      }
    finally:
      self.wg.freeConfig(cfg_ptr)

  def read_stats(self, interface: str) -> dict:
    cfg_ptr = self.wg.readStats(interface.encode("utf-8"))
    if not cfg_ptr: return {}

    cfg = cfg_ptr.contents

    try:
      return {
        "last_handshake": cfg.LastHandshakeTime.decode("utf-8") if cfg.LastHandshakeTime else "",
        "transfer": cfg.Transfer.decode("utf-8") if cfg.Transfer else ""
      }
    finally:
      self.wg.freeStats(cfg_ptr)

class TunnelCreationDialog(QDialog):
  def __init__(self, priv_key: str, pub_key: str, parent=None):
    super().__init__(parent)
    self.setWindowTitle("Create new tunnel")
    self.setFixedSize(500, 400)

    self.priv_key = priv_key
    self.pub_key = pub_key

    self.name_input = None
    self.config_dir = None

    self.init_ui()

  def init_ui(self) -> None:
    layout = QVBoxLayout()

    form_layout = QFormLayout()
    self.name_input = QLineEdit()
    self.public_key = QLineEdit()
    self.public_key.setText(self.pub_key)
    form_layout.addRow("Name:", self.name_input)
    form_layout.addRow("Public Key:", self.public_key)

    self.text_edit = QTextEdit()
    self.text_edit.setFontFamily("Monospace")
    self.text_edit.setFontPointSize(10)
    self.text_edit.setPlainText("[Interface]" + "\n" + f"PrivateKey = {self.priv_key}")

    button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
    button_box.setStyleSheet(
      """
      QPushButton {
        padding: 5px;
        border: 1px solid #4FC3F7;
        border-radius: 3px;
      }
      QPushButton:hover {
        background: #B3E5FC;
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
        os.path.join(self.config_dir, f"{name}.conf"),
        "w",
        encoding="utf-8"
      ) as f:
        f.write(self.text_edit.toPlainText())

        self.accept()
    except Exception as e:
      QMessageBox.warning(self, "Error", f"Failed to save configuration file: {str(e)}")

  def validate_config(self, name: str) -> bool:
    if not name:
      QMessageBox.warning(self, "Error", "Tunnel name cannot be empty")
      return False

    if not re.match(r"^[a-zA-Z0-9-]+$", name):
      QMessageBox.warning(
        self,
        "Error",
        "Tunnel name can only containt letters, numbers and hyphens"
      )
      return False

    folders = ["/etc/wireguard", "/usr/local/etc/wireguard"]
    for folder in folders:
      if os.path.isdir(folder):
        self.config_dir = folder
        break

    if not self.config_dir:
      QMessageBox.warning(self, "Error", "Configuration directories do not exist")
      return False

    if not os.access(self.config_dir, os.W_OK):
      QMessageBox.warning(
        self,
        "Error",
        f"No write permission for {self.config_dir}"
      )
      return

    if os.path.isfile(os.path.join(self.config_dir, f"{name}.conf")):
      QMessageBox.warning(self, "Error", f"Configuration file for {name} already exists")
      return False

    return True

class TunnelEditDialog(QDialog):
  def __init__(self, tunnel_name: str, parent=None):
    super().__init__(parent)
    self.setWindowTitle(f"Edit the tunnel {tunnel_name}")
    self.setFixedSize(500, 400)

    self.tunnel_name = tunnel_name
    self.config_file = None

    self.init_ui()

  def init_ui(self) -> None:
    layout = QVBoxLayout()

    self.text_edit = QTextEdit()
    self.text_edit.setFontFamily("Monospace")
    self.text_edit.setFontPointSize(10)
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
        background: #B3E5FC;
      }
      """
    )
    button_box.accepted.connect(self.save_config)
    button_box.rejected.connect(self.reject)
    layout.addWidget(button_box)

    self.setLayout(layout)

    self.load_config()

  def load_config(self) -> None:
    paths = [
      f"/etc/wireguard/{self.tunnel_name}.conf",
      f"/usr/local/etc/wireguard/{self.tunnel_name}.conf"
    ]

    for path in paths:
      if os.path.isfile(path):
        self.config_file = path
        break

    if not self.config_file:
      QMessageBox.warning(
        self,
        "Error",
        f"Configuration file for {self.tunnel_name} not found",
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
    try:
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

class TunnelButton(QPushButton):
  def __init__(self, name: str, is_active: bool = False, parent=None):
    super().__init__(name, parent)
    self.is_selected = False
    self.is_active = is_active

    self.update_style()

  def update_style(self) -> None:
    background = "#B3E5FC" if self.is_selected else "transparent"

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
        background: #B3E5FC;
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

class TunnelConfigWidget(QWidget):
  def __init__(self, name: str, config: dict, stats: dict, is_active: bool = False, parent=None):
    super().__init__(parent)
    self.layout = QVBoxLayout()
    self.layout.setContentsMargins(0, 0, 0, 0)

    self.wireguard = Wireguard()

    self.name = name
    self.is_active = is_active

    self.field_widget = {}

    interface_group = QGroupBox(f"Interface: {name}")
    interface_group.setStyleSheet(
      """
      QGroupBox {
        border: 1px solid black;
        margin-top: 10px;
        font-size: 12px;
      }
      QGroupBox:title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
      }
      """
    )
    interface_layout = QVBoxLayout()
    interface_layout.setContentsMargins(10, 10, 10, 10)
    interface_layout.setSpacing(5)

    status_layout = QHBoxLayout()
    status_label = QLabel("Status:")
    status_label.setStyleSheet("font-weight: bold;")
    status_label.setFixedWidth(80)
    status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
    self.status_indicator = QLabel()
    self.status_indicator.setFixedSize(12, 12)
    self.status_indicator.setStyleSheet(
      f"background-color: {"#4CAF50" if is_active else "#808080"}; border-radius: 5px;"
    )
    status_text = QLabel("Active" if is_active else "Inactive")
    status_layout.addWidget(status_label)
    status_layout.addWidget(self.status_indicator)
    status_layout.addWidget(status_text)
    status_layout.addStretch()
    interface_layout.addLayout(status_layout)

    inteface_fields = [
      ("Public Key:", config.get("interface_pub_key", "")),
      ("Listen Port:", str(
        config.get(
          "interface_listen_port"
        )) if config.get("interface_listen_port", 0) else ""),
      ("Address:", config.get("interface_address", "")),
      ("DNS:", config.get("interface_dns", ""))
    ]
    for label_text, value in inteface_fields:
      field_layout = QHBoxLayout()
      label = QLabel(label_text)
      label.setStyleSheet("font-weight: bold;")
      label.setFixedWidth(80)
      label.setAlignment(Qt.AlignmentFlag.AlignRight)
      if value:
        value_edit = QLineEdit(value)
        value_edit.setStyleSheet("QLineEdit { border: none; }")
        value_edit.setReadOnly(True)
        field_layout.addWidget(label)
        field_layout.addWidget(value_edit)
        interface_layout.addLayout(field_layout)

    button_layout = QHBoxLayout()
    button_layout.addSpacerItem(QSpacerItem(85, 0))
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
        background: #B3E5FC;
      }
      """
    )

    button_layout.addWidget(self.active_button)
    button_layout.addStretch()
    interface_layout.addLayout(button_layout)

    interface_group.setLayout(interface_layout)

    peer_group = QGroupBox("Peer")
    peer_group.setStyleSheet(
      """
      QGroupBox {
        border: 1px solid black;
        margin-top: 10px;
        font-size: 12px;
      }
      QGroupBox:title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
      }
      """
    )
    peer_layout = QVBoxLayout()
    peer_layout.setContentsMargins(10, 10, 10, 10)
    peer_layout.setSpacing(5)

    peer_fields = [
      ("Public Key:", config.get("peer_pub_key", "")),
      ("Allowed IPs:", config.get("peer_allowed_ips", "")),
      ("Endpoint:", config.get("peer_endpoint_address", "")),
      ("P_Keepalive:", config.get("peer_keep_alive", "")),
      ("Last_HS:", stats.get("last_handshake", "")),
      ("Transfer:", stats.get("transfer", ""))
    ]
    for label_text, value in peer_fields:
      field_layout = QHBoxLayout()
      label = QLabel(label_text)
      label.setStyleSheet("font-weight: bold;")
      label.setFixedWidth(80)
      label.setAlignment(Qt.AlignmentFlag.AlignRight)
      if value:
        value_edit = QLineEdit(value)
        value_edit.setStyleSheet("QLineEdit { border: none; }")
        value_edit.setReadOnly(True)
        field_layout.addWidget(label)
        field_layout.addWidget(value_edit)
        if label_text in ("Last_HS:", "Transfer:"):
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
      if "Last_HS:" in self.field_widget:
        self.field_widget["Last_HS:"].setText(stats.get("last_handshake", ""))
      if "Transfer:" in self.field_widget:
        self.field_widget["Transfer:"].setText(stats.get("transfer", ""))

class MainWindow(QMainWindow):
  def __init__(self):
    super().__init__()
    self.active_icon, self.default_icon = Config.get_icons()

    self.setWindowTitle("WireGuard")
    self.setWindowIcon(QIcon(self.default_icon))
    self.setFixedSize(750, 550)

    self.wireguard = Wireguard()

    self.edit_button = None
    self.selected_tunnel = None
    self.selected_button = None

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
    self.left_panel.customContextMenuRequested.connect(self.show_context_menu)

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
    self.button_panel.setStyleSheet("QPushButton:hover { background: #B3E5FC; }")
    self.buttons_layout = QHBoxLayout()
    self.buttons_layout.setContentsMargins(0, 0, 0, 0)

    add_tunnel_btn = QPushButton("⚙️ Add Tunnel")
    add_tunnel_btn.setFixedSize(110, 25)
    add_tunnel_menu = QMenu(self)
    import_action = add_tunnel_menu.addAction("Import tunnel(s) from file...")
    import_action.triggered.connect(self.import_tunnels)
    add_action = add_tunnel_menu.addAction("Add empty tunnel...")
    add_action.triggered.connect(self.create_tunnel)
    add_tunnel_btn.setMenu(add_tunnel_menu)
    self.buttons_layout.addWidget(add_tunnel_btn)

    separator_one = QLabel("|")
    separator_one.setFixedSize(8, 25)
    self.buttons_layout.addWidget(separator_one)

    delete_button = QPushButton("❌")
    delete_button.setFixedSize(50, 25)
    delete_button.setToolTip("Remove selected tunnel(s)...")
    delete_button.clicked.connect(self.remove_tunnel)
    self.buttons_layout.addWidget(delete_button)

    separator_two = QLabel("|")
    separator_two.setFixedSize(8, 25)
    self.buttons_layout.addWidget(separator_two)

    export_btn = QPushButton("📥")
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
    logs_text = QLabel("Logs are currently unsupported")
    logs_text.setStyleSheet("font-weight: bold; font-size: 18px;")
    layout.addWidget(logs_text, alignment=Qt.AlignmentFlag.AlignCenter)

    self.logs_tab.setLayout(layout)

  def closeEvent(self, event: QCloseEvent) -> None:
    event.ignore()
    self.hide()

    super().closeEvent(event)

  def resizeEvent(self, event: QResizeEvent) -> None:
    self.left_panel.setFixedWidth(self.width() // 3)
    self.button_panel.setMaximumWidth(self.width() // 3)

    super().resizeEvent(event)

  def has_active_tunnel(self) -> bool:
    for interface in self.wireguard.read_interfaces_name():
      config = self.wireguard.read_config(interface)
      if config.get("interface_listen_port", 0) != 0: return True

    return False

  def set_icon(self) -> None:
    is_active = self.has_active_tunnel()

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
        except subprocess.CalledProcessError as e:
          QMessageBox.warning(self, "Error", f"Failied to stop tunnel: {str(e)}")

    QApplication.quit()

  def load_interfaces(self) -> None:
    if hasattr(self, "left_panel"):
      self.left_widget.deleteLater()

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

      self.left_layout.addWidget(button)

    self.set_icon()

    self.left_layout.addStretch()

  # TODO: (heycatch) upgrade logic in show_contenxt_menu.
  def show_context_menu(self, position: QPoint) -> None:
    menu = QMenu(self)

    toggle_action = menu.addAction("Toggle")
    toggle_action.setEnabled(False)

    menu.addSeparator()

    menu.addAction("Import tunnel(s) from file...", self.import_tunnels)
    menu.addAction("Add empty tunnel...", self.create_tunnel)
    export_action = menu.addAction("Export all tunnels to zip...")
    export_action.setEnabled(False)

    menu.addSeparator()

    edit_action = menu.addAction("Edit selected tunnel...")
    edit_action.setEnabled(False)
    remove_action = menu.addAction("Remove selected tunnel(s)...")
    remove_action.setEnabled(False)
    select_all_action = menu.addAction("Select all")
    select_all_action.setEnabled(False)

    menu.exec(self.tunnels_tab.mapToGlobal(position))

  def create_tunnel(self) -> None:
    priv_key, pub_key = self.wireguard.generate_keys()

    dialog = TunnelCreationDialog(priv_key, pub_key, self)
    if dialog.exec() == QDialog.DialogCode.Accepted:
      self.load_interfaces()

  def show_tunnel(self, name: str) -> None:
    self.selected_tunnel = name
    self.selected_button = None

    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()

      if isinstance(widget, TunnelButton):
        if widget.text() == name:
          widget.set_selected(True)

          self.selected_button = widget
        else:
          widget.set_selected(False)

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
      QMessageBox.warning(self, "Error", "Falied to read the configuration file")

      import_btn = QPushButton("Import tunnel(s) from file")
      import_btn.setStyleSheet("font-weight: bold; font-size: 15px;")
      import_btn.clicked.connect(self.import_tunnels)
      self.right_layout.addStretch()
      self.right_layout.addWidget(import_btn, alignment=Qt.AlignmentFlag.AlignCenter)
      self.right_layout.addStretch()
      self.right_panel.setLayout(self.right_layout)

      self.set_icon(False)

      return

    is_active = config.get("interface_listen_port", 0) != 0
    config_widget = TunnelConfigWidget(name, config, stats, is_active=is_active)
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
        background: #B3E5FC;
      }
      """
    )
    self.edit_button.clicked.connect(lambda: self.edit_tunnel())
    self.bottom_layout.addWidget(self.edit_button)

  def edit_tunnel(self) -> None:
    dialog = TunnelEditDialog(self.selected_tunnel, self)
    if dialog.exec() == QDialog.DialogCode.Accepted:
      self.show_tunnel(self.selected_tunnel)

  def toggle_tunnel(self, is_active: bool) -> None:
    if not self.selected_tunnel: return

    new_state = not is_active
    try:
      if new_state:
        subprocess.run(["wg-quick", "up", self.selected_tunnel], check=True)
      else:
        subprocess.run(["wg-quick", "down", self.selected_tunnel], check=True)
    except subprocess.CalledProcessError as e:
      QMessageBox.warning(self, "Error", f"Failied to toggle tunnel: {str(e)}")
      return

    for i in range(self.left_layout.count()):
      widget = self.left_layout.itemAt(i).widget()
      if isinstance(widget, TunnelButton) and widget.text() == self.selected_tunnel:
        widget.is_active = new_state
        widget.update()
        break

    self.set_icon()

    self.show_tunnel(self.selected_tunnel)

  def remove_tunnel(self) -> None:
    if not self.selected_tunnel: return

    reply = QMessageBox.question(
      self,
      "Confirm",
      f"Are you sure you want to remove tunnel {self.selected_tunnel}?",
      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )

    if reply == QMessageBox.StandardButton.Yes:
      paths = [
        f"/etc/wireguard/{self.selected_tunnel}.conf",
        f"/usr/local/etc/wireguard/{self.selected_tunnel}.conf"
      ]

      for path in paths:
        if os.path.isfile(path):
          try:
            if not os.access(path, os.W_OK):
              QMessageBox.warning(
                self,
                "Error",
                f"No delete permission for {path}"
              )
              return

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

      while self.right_layout.count():
        item = self.right_layout.takeAt(0)
        if item.widget(): item.widget().deleteLater()

      self.selected_tunnel = None
      self.selected_button = None

      import_btn = QPushButton("Import tunnel(s) from file")
      import_btn.setStyleSheet("font-weight: bold; font-size: 15px;")
      import_btn.clicked.connect(self.import_tunnels)
      self.right_layout.addStretch()
      self.right_layout.addWidget(import_btn, alignment=Qt.AlignmentFlag.AlignCenter)
      self.right_layout.addStretch()
      self.right_panel.setLayout(self.right_layout)

      self.load_interfaces()

  def import_tunnels(self) -> None:
    file_dialog = QFileDialog(self)
    file_dialog.setNameFilter("Config files (*.conf)")
    file_dialog.setFileMode(QFileDialog.ExistingFiles)

    if file_dialog.exec():
      config_dir = None
      count = 0

      folders = ["/etc/wireguard", "/usr/local/etc/wireguard"]
      for folder in folders:
        if os.path.isdir(folder):
          config_dir = folder
          break

      if not config_dir:
        QMessageBox.warning(self, "Error", "Configuration directories do not exist")
        return

      if not os.access(config_dir, os.W_OK):
        QMessageBox.warning(
          self,
          "Error",
          f"No import permission for {config_dir}"
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
        f"Successfully imported {count} tunnel(s)"
      )

      self.load_interfaces()
    else:
      QMessageBox.warning(self, "Error", "No files were imported")

  def export_tunnels(self) -> None:
    config_dir = None

    folders = ["/etc/wireguard", "/usr/local/etc/wireguard"]
    for folder in folders:
      if os.path.isdir(folder):
        config_dir = folder
        break

    if not config_dir:
      QMessageBox.warning(self, "Error", "Configuration directories do not exist")
      return

    conf_files = [f for f in os.listdir(config_dir) if f.endswith(".conf")]
    if not conf_files:
      QMessageBox.warning(self, "Error", "Configuration files do not exist")
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
        f"Successfully exported {len(conf_files)} configurations to:\n{zip_path}"
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
