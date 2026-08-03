import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib, Pango
import os
import threading
import traceback
import pkcs11

from encrypta3.backends.vault import auto_discover_pkcs11, is_vault, encrypt_path, decrypt_path

TARGET_ENTRY_URI = 1

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_title("EncryptA3")
        self.set_default_size(600, 500)
        self.set_border_width(10)
        
        self.pkcs11_lib_path = auto_discover_pkcs11()
        self.pkcs11_lib = None
        if self.pkcs11_lib_path:
            try:
                self.pkcs11_lib = pkcs11.lib(self.pkcs11_lib_path)
            except Exception:
                pass
                
        self.active_operation = False
        self.selected_path = None
        self.is_decrypt_mode = False
        
        self.build_ui()
        self.setup_drag_and_drop()
        
        # Token status poll
        self.poll_source = GLib.timeout_add(2000, self.poll_token_status)
        self.poll_token_status()

    def build_ui(self):
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.add(self.stack)
        
        # --- EMPTY PAGE ---
        self.empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.empty_box.set_valign(Gtk.Align.CENTER)
        self.empty_box.set_halign(Gtk.Align.CENTER)
        
        icon = Gtk.Image.new_from_icon_name("document-new", Gtk.IconSize.DIALOG)
        icon.set_pixel_size(128)
        self.empty_box.pack_start(icon, False, False, 0)
        
        lbl = Gtk.Label(label="Arraste e solte um arquivo ou pasta para começar")
        lbl.set_markup("<big><b>Arraste um arquivo ou pasta para começar</b></big>")
        self.empty_box.pack_start(lbl, False, False, 0)
        
        btn_select = Gtk.Button(label="Ou clique aqui para selecionar")
        btn_select.connect("clicked", self.on_select_file_clicked)
        btn_select.set_halign(Gtk.Align.CENTER)
        self.empty_box.pack_start(btn_select, False, False, 0)
        
        self.stack.add_named(self.empty_box, "empty")
        
        # --- ACTION PAGE ---
        self.action_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        
        # Header
        self.lbl_action_title = Gtk.Label()
        self.lbl_action_title.set_markup("<big><b>Ação</b></big>")
        self.lbl_action_title.set_halign(Gtk.Align.START)
        self.action_box.pack_start(self.lbl_action_title, False, False, 0)
        
        self.lbl_filename = Gtk.Label()
        self.lbl_filename.set_halign(Gtk.Align.START)
        self.lbl_filename.set_ellipsize(Pango.EllipsizeMode.END)
        self.action_box.pack_start(self.lbl_filename, False, False, 0)
        
        self.action_box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)
        
        # Form
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(10)
        self.action_box.pack_start(grid, False, False, 0)
        
        # Auth Container (Stack to swap between Encrypt Checkboxes and Decrypt RadioButtons)
        self.auth_stack = Gtk.Stack()
        self.auth_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        
        # Encrypt Auth (CheckButtons - allows both)
        box_enc_auth = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.check_enc_token = Gtk.CheckButton(label="Usar Token A3")
        self.check_enc_pwd = Gtk.CheckButton(label="Adicionar Senha de Recuperação (Backup)")
        self.check_enc_token.set_active(True)
        self.check_enc_token.connect("toggled", self.on_auth_method_changed)
        self.check_enc_pwd.connect("toggled", self.on_auth_method_changed)
        box_enc_auth.pack_start(self.check_enc_token, False, False, 0)
        box_enc_auth.pack_start(self.check_enc_pwd, False, False, 0)
        self.auth_stack.add_named(box_enc_auth, "encrypt")
        
        # Decrypt Auth (RadioButtons - exclusive)
        box_dec_auth = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.rb_dec_token = Gtk.RadioButton.new_with_label_from_widget(None, "Desbloquear com Token A3")
        self.rb_dec_pwd = Gtk.RadioButton.new_with_label_from_widget(self.rb_dec_token, "Desbloquear com Senha")
        self.rb_dec_token.connect("toggled", self.on_auth_method_changed)
        box_dec_auth.pack_start(self.rb_dec_token, False, False, 0)
        box_dec_auth.pack_start(self.rb_dec_pwd, False, False, 0)
        self.auth_stack.add_named(box_dec_auth, "decrypt")
        
        grid.attach(self.auth_stack, 0, 0, 2, 1)
        
        # PIN Entry
        self.entry_pin = Gtk.Entry()
        self.entry_pin.set_visibility(False)
        self.entry_pin.set_placeholder_text("Digite o PIN do Token")
        self.entry_pin.connect("activate", self.on_start_clicked)
        self.entry_pin.set_hexpand(True)
        
        # PWD Entry
        self.entry_pwd = Gtk.Entry()
        self.entry_pwd.set_visibility(False)
        self.entry_pwd.set_placeholder_text("Digite a Senha de Recuperação")
        self.entry_pwd.connect("activate", self.on_start_clicked)
        self.entry_pwd.set_hexpand(True)
        
        # Vbox for entries
        self.entries_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.entries_box.pack_start(self.entry_pin, False, False, 0)
        self.entries_box.pack_start(self.entry_pwd, False, False, 0)
        
        grid.attach(self.entries_box, 0, 1, 1, 1)
        
        self.btn_toggle_vis = Gtk.ToggleButton()
        self.btn_toggle_vis.set_image(Gtk.Image.new_from_icon_name("view-reveal-symbolic", Gtk.IconSize.BUTTON))
        self.btn_toggle_vis.connect("toggled", self.on_toggle_visibility)
        self.btn_toggle_vis.set_valign(Gtk.Align.CENTER)
        grid.attach(self.btn_toggle_vis, 1, 1, 1, 1)
        
        # Options
        self.options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.options_box.set_margin_top(10)
        self.check_wipe = Gtk.CheckButton(label="Apagar arquivo original com segurança após cifrar")
        self.box_stealth = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.check_stealth = Gtk.CheckButton(label="Modo Furtivo")
        self.check_stealth.set_tooltip_text("Esconde a assinatura do cabeçalho.")
        
        self.entry_stealth_ext = Gtk.Entry()
        self.entry_stealth_ext.set_placeholder_text("Extensão (Ex: .mp4)")
        self.entry_stealth_ext.set_sensitive(False)
        
        def on_stealth_toggled(btn):
            self.entry_stealth_ext.set_sensitive(btn.get_active())
        self.check_stealth.connect("toggled", on_stealth_toggled)
        
        self.box_stealth.pack_start(self.check_stealth, False, False, 0)
        self.box_stealth.pack_start(self.entry_stealth_ext, False, False, 0)
        
        box_pim = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        box_pim.pack_start(Gtk.Label(label="PIM (Multiplicador de Iterações):"), False, False, 0)
        self.spin_pim = Gtk.SpinButton.new_with_range(1, 100, 1)
        self.spin_pim.set_value(1)
        self.spin_pim.set_tooltip_text("Valores maiores aumentam a segurança da senha de recuperação contra força bruta, mas o arquivo demora mais para abrir.")
        box_pim.pack_start(self.spin_pim, False, False, 0)
        
        self.options_box.pack_start(self.check_wipe, False, False, 0)
        self.options_box.pack_start(self.box_stealth, False, False, 0)
        self.options_box.pack_start(box_pim, False, False, 0)
        
        grid.attach(self.options_box, 0, 3, 2, 1)
        
        self.action_box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)
        
        # Token status
        self.box_token_status = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.img_token_status = Gtk.Image.new_from_icon_name("network-error", Gtk.IconSize.BUTTON)
        self.lbl_token_status = Gtk.Label(label="Buscando token...")
        self.box_token_status.pack_start(self.img_token_status, False, False, 0)
        self.box_token_status.pack_start(self.lbl_token_status, False, False, 0)
        self.action_box.pack_start(self.box_token_status, False, False, 0)
        
        # Bottom controls
        self.lbl_feedback = Gtk.Label()
        self.lbl_feedback.set_line_wrap(True)
        self.lbl_feedback.set_xalign(0)
        self.action_box.pack_start(self.lbl_feedback, False, False, 0)
        
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.action_box.pack_start(self.progress_bar, False, False, 0)
        
        bbox = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bbox.set_layout(Gtk.ButtonBoxStyle.END)
        
        self.btn_back = Gtk.Button(label="Voltar")
        self.btn_back.connect("clicked", self.on_back_clicked)
        self.btn_start = Gtk.Button(label="Iniciar")
        self.btn_start.get_style_context().add_class("suggested-action")
        self.btn_start.connect("clicked", self.on_start_clicked)
        
        bbox.pack_start(self.btn_back, False, False, 0)
        bbox.pack_start(self.btn_start, False, False, 0)
        
        self.action_box.pack_end(bbox, False, False, 0)
        
        self.stack.add_named(self.action_box, "action")
        self.show_all()
        self.options_box.show_all()
        self.progress_bar.hide()
        
    def setup_drag_and_drop(self):
        # We accept URIs (like file://...)
        self.drag_dest_set(Gtk.DestDefaults.ALL, [], Gdk.DragAction.COPY)
        self.drag_dest_add_uri_targets()
        self.connect("drag-data-received", self.on_drag_data_received)
        
    def on_drag_data_received(self, widget, drag_context, x, y, data, info, time):
        if self.active_operation:
            drag_context.finish(False, False, time)
            return
            
        uris = data.get_uris()
        if uris:
            uri = uris[0]
            if uri.startswith("file://"):
                path = uri[7:]
                # handle url encoding
                from urllib.parse import unquote
                path = unquote(path)
                self.load_file(path)
        drag_context.finish(True, False, time)
        
    def on_select_file_clicked(self, widget):
        dialog = Gtk.FileChooserDialog(
            title="Selecione um arquivo ou pasta",
            parent=self,
            action=Gtk.FileChooserAction.OPEN
        )
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.load_file(dialog.get_filename())
        dialog.destroy()
        
    def load_file(self, filepath):
        if not os.path.exists(filepath):
            return
            
        self.selected_path = filepath
        self.lbl_filename.set_text(filepath)
        
        # Check if it's a vault
        self.is_decrypt_mode = is_vault(filepath)
        
        if self.is_decrypt_mode:
            self.lbl_action_title.set_markup("<big><b>Descriptografar Arquivo</b></big>")
            self.btn_start.set_label("Descriptografar")
            self.options_box.hide() # Decrypt parameters are read from header
            self.auth_stack.set_visible_child_name("decrypt")
        else:
            self.lbl_action_title.set_markup("<big><b>Criptografar Arquivo</b></big>")
            self.btn_start.set_label("Criptografar")
            self.options_box.show()
            self.auth_stack.set_visible_child_name("encrypt")
            
        self.on_auth_method_changed(None)
            
        self.lbl_feedback.set_text("")
        self.entry_pin.set_text("")
        self.entry_pwd.set_text("")
        self.progress_bar.set_fraction(0)
        self.progress_bar.hide()
        
        self.stack.set_visible_child_name("action")
        if self.entry_pin.get_visible():
            self.entry_pin.grab_focus()
        elif self.entry_pwd.get_visible():
            self.entry_pwd.grab_focus()

    def on_back_clicked(self, widget):
        if self.active_operation:
            return
        # Security: Limpar campos imediatamente
        self.entry_pin.set_text("")
        self.entry_pwd.set_text("")
        self.selected_path = None
        self.stack.set_visible_child_name("empty")

    def on_auth_method_changed(self, widget):
        if self.is_decrypt_mode:
            use_pin = self.rb_dec_token.get_active()
            use_pwd = not use_pin
        else:
            use_pin = self.check_enc_token.get_active()
            use_pwd = self.check_enc_pwd.get_active()
            
        self.entry_pin.set_visible(use_pin)
        self.entry_pwd.set_visible(use_pwd)
        
        if not use_pin and not use_pwd:
            self.btn_start.set_sensitive(False)
        else:
            self.btn_start.set_sensitive(True)

    def on_toggle_visibility(self, widget):
        self.entry_pin.set_visibility(self.btn_toggle_vis.get_active())
        self.entry_pwd.set_visibility(self.btn_toggle_vis.get_active())

    def poll_token_status(self):
        if self.active_operation:
            return True # Pausar polling durante operações para evitar concorrência no middleware
            
        has_token = False
        if self.pkcs11_lib:
            try:
                tokens = list(self.pkcs11_lib.get_tokens())
                if len(tokens) > 0:
                    has_token = True
            except Exception:
                pass
                
        if has_token:
            self.img_token_status.set_from_icon_name("network-transmit-receive", Gtk.IconSize.BUTTON)
            self.lbl_token_status.set_text("Token detectado e pronto.")
            self.lbl_token_status.get_style_context().add_class("success")
            
            # Avisa internamente se o token acabou de ser plugado para não forçar a interface se o usuário tiver desmarcado manualmente
            if not hasattr(self, '_token_was_present') or not self._token_was_present:
                self._token_was_present = True
                if not self.is_decrypt_mode and not self.active_operation:
                    self.check_enc_token.set_active(True)
                elif self.is_decrypt_mode and not self.active_operation:
                    self.rb_dec_token.set_active(True)
        else:
            self._token_was_present = False
            self.img_token_status.set_from_icon_name("network-error", Gtk.IconSize.BUTTON)
            self.lbl_token_status.set_text("Nenhum token detectado.")
            
        return True # Mantem o timeout rodando

    def set_ui_sensitive(self, sensitive):
        self.btn_start.set_sensitive(sensitive)
        self.btn_back.set_sensitive(sensitive)
        self.entry_pin.set_sensitive(sensitive)
        self.entry_pwd.set_sensitive(sensitive)
        self.options_box.set_sensitive(sensitive)
        self.check_enc_token.set_sensitive(sensitive)
        self.check_enc_pwd.set_sensitive(sensitive)
        self.rb_dec_token.set_sensitive(sensitive)
        self.rb_dec_pwd.set_sensitive(sensitive)

    def on_start_clicked(self, widget):
        if self.active_operation or not self.selected_path:
            return
            
        pin_val = self.entry_pin.get_text() if self.entry_pin.get_visible() else None
        pwd_val = self.entry_pwd.get_text() if self.entry_pwd.get_visible() else None
        
        if self.entry_pin.get_visible() and not pin_val:
            self.show_error("Por favor, digite o PIN.")
            self.entry_pin.grab_focus()
            return
            
        if self.entry_pwd.get_visible() and not pwd_val:
            self.show_error("Por favor, digite a Senha.")
            self.entry_pwd.grab_focus()
            return
            
        # Dialog de confirmacao se for wipe
        if not self.is_decrypt_mode and self.check_wipe.get_active():
            dialog = Gtk.MessageDialog(
                transient_for=self,
                flags=0,
                message_type=Gtk.MessageType.WARNING,
                buttons=Gtk.ButtonsType.OK_CANCEL,
                text="Atenção: Destruição Permanente"
            )
            dialog.format_secondary_text(f"O arquivo original:\n{self.selected_path}\nserá destruído permanentemente após a criptografia. Você tem certeza?")
            response = dialog.run()
            dialog.destroy()
            if response != Gtk.ResponseType.OK:
                return

        # Limpar campo da UI (Nota: CPython não garante zeroing de strings na memória, o GC fará a limpeza eventualmente)
        self.entry_pin.set_text("")
        self.entry_pwd.set_text("")
        
        self.active_operation = True
        self.set_ui_sensitive(False)
        self.progress_bar.show()
        self.progress_bar.set_fraction(0)
        self.lbl_feedback.set_markup("<i>Processando... Não remova o token.</i>")
        
        pin = pin_val
        pwd = pwd_val
        
        wipe = self.check_wipe.get_active()
        stealth = self.check_stealth.get_active()
        stealth_ext = self.entry_stealth_ext.get_text().strip()
        pim = int(self.spin_pim.get_value())
        
        # Executar em thread separada para não travar a GUI
        thread = threading.Thread(target=self.run_crypto_thread, args=(self.selected_path, pin, pwd, wipe, stealth, stealth_ext, pim))
        thread.daemon = True
        thread.start()
        
    def show_error(self, msg):
        self.lbl_feedback.set_markup(f"<span foreground='red'>{GLib.markup_escape_text(msg)}</span>")
        
    def update_progress_idle(self, fraction):
        self.progress_bar.set_fraction(fraction)
        return False
        
    def thread_finished_idle(self, success, result_msg):
        self.active_operation = False
        self.set_ui_sensitive(True)
        if success:
            self.progress_bar.set_fraction(1.0)
            self.lbl_feedback.set_markup(f"<span foreground='green'>Sucesso!</span> {GLib.markup_escape_text(result_msg)}")
            # Ir para empty page dps de um tempinho
            GLib.timeout_add(3000, lambda: self.stack.set_visible_child_name("empty") if not self.active_operation else False)
        else:
            self.progress_bar.hide()
            self.show_error(result_msg)
        return False

    def run_crypto_thread(self, target_path, pin, pwd, wipe, stealth, stealth_ext, pim):
        success = False
        msg = ""
        output_path = ""
        try:
            def prog_cb(fraction):
                GLib.idle_add(self.update_progress_idle, fraction)
                
            if self.is_decrypt_mode:
                out_dir = os.path.dirname(target_path)
                output_path = decrypt_path(target_path, out_dir, pkcs11_lib=self.pkcs11_lib_path, pin=pin, recovery_password=pwd, progress_callback=prog_cb)
                msg = f"Arquivo salvo em: {output_path}"
                success = True
            else:
                ext = stealth_ext if stealth else ".ea3"
                if not ext.startswith('.') and ext != "":
                    ext = "." + ext
                
                if stealth and ext != "":
                    base = os.path.splitext(target_path)[0]
                    output_path = base + ext
                else:
                    output_path = target_path + ext
                    
                if os.path.exists(output_path):
                    if stealth and ext != "":
                        output_path = base + "_enc" + ext
                    else:
                        output_path = target_path + "_enc" + ext # prevent overwrite on stealth
                encrypt_path(target_path, output_path, pkcs11_lib=self.pkcs11_lib_path, pin=pin, recovery_password=pwd, wipe_original=wipe, stealth_mode=stealth, pim=pim, progress_callback=prog_cb)
                msg = f"Arquivo salvo em: {output_path}"
                success = True
        except Exception as e:
            traceback.print_exc()
            # Limpeza de lixo em caso de erro no meio da operacao (ex: token arrancado)
            if output_path and os.path.exists(output_path) and os.path.isfile(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            # Mensagens mais amigaveis
            error_str = str(e)
            if "UserNotLoggedIn" in error_str or "PinIncorrect" in error_str:
                msg = "Erro: PIN incorreto."
            elif "Token" in error_str or "SessionClosed" in error_str or "DeviceError" in error_str:
                msg = "Erro: Comunicação com o Token falhou (foi removido?)."
            else:
                msg = f"Erro: {error_str}"
                
        finally:
            GLib.idle_add(self.thread_finished_idle, success, msg)
