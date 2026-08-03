import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gio, GLib
from encrypta3.gui.main_window import MainWindow

class EncryptA3App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.github.diegoribeirodesouza.encrypta3",
                         flags=Gio.ApplicationFlags.FLAGS_NONE)
        GLib.set_prgname("encrypta3")
        Gtk.Window.set_default_icon_name("dialog-password")
        self.window = None

    def do_activate(self):
        if not self.window:
            self.window = MainWindow(application=self)
        self.window.present()

def main():
    app = EncryptA3App()
    app.run(None)

if __name__ == '__main__':
    main()
