"""
PWNShiftEnter - Terminator plugin shipped with the pwn gem.

WHY THIS EXISTS
---------------
libvte (the terminal widget used by Terminator, GNOME Terminal, Tilix,
xfce4-terminal, ...) does *not* implement xterm's modifyOtherKeys
(CSI >4;Nm) nor the kitty keyboard protocol (CSI >1u). See upstream
GNOME/vte issues #2601 / #2607.

That means a physical Shift+Enter and a plain Enter both reach the
inner application (tmux -> Reline -> pwn-ai) as an identical single
0x0D byte -- no amount of tmux `extended-keys on`, `terminal-features
extkeys`, or in-app CSI requests can distinguish them, because VTE
never encoded the modifier in the first place.

pwn-ai's PWNMultiLineInput needs Shift+Enter to insert a newline and
plain Enter to submit. This plugin sits *above* VTE, at the GTK
key-press-event layer, intercepts <Shift>Return before VTE encodes
it, and injects the xterm modifyOtherKeys sequence CSI 27;2;13~
(SHIFT_ENTER_SEQS[1] in lib/pwn/plugins/repl.rb) directly into the
pty via Vte.Terminal.feed_child.

The sequence is the same one tmux would emit for S-Enter to a pane
in Ext-mode-1, so it works identically whether you are inside tmux
or running pwn directly in a Terminator split.

INSTALL
-------
This file is auto-installed by
PWN::Plugins::REPL::PWNMultiLineInput#ensure_vte_shift_enter to:

    ~/.config/terminator/plugins/pwn_shift_enter.py

and enabled in ~/.config/terminator/config under `enabled_plugins`.
Terminator must be restarted once for the plugin to load.
"""
import gi
gi.require_version('Gdk', '3.0')
gi.require_version('Vte', '2.91')
from gi.repository import Gdk

import terminatorlib.plugin as plugin
from terminatorlib.terminator import Terminator
from terminatorlib.util import dbg, err

AVAILABLE = ['PWNShiftEnter']

# xterm modifyOtherKeys / tmux extended-keys encoding for Shift+Enter.
# Matches SHIFT_ENTER_SEQS[1] in /opt/pwn/lib/pwn/plugins/repl.rb and is
# what tmux 3.5+ re-encodes S-Enter as when a pane requests CSI >4;1m.
S_ENTER_SEQ = b'\x1b[27;2;13~'

# Only fire on *pure* Shift+Return / Shift+KP_Enter. Ctrl / Alt / Super
# combinations fall through untouched so users keep whatever they have
# bound there.
CONSUME_MODS = (
    Gdk.ModifierType.CONTROL_MASK
    | Gdk.ModifierType.MOD1_MASK    # Alt
    | Gdk.ModifierType.SUPER_MASK
    | Gdk.ModifierType.HYPER_MASK
    | Gdk.ModifierType.META_MASK
)


class PWNShiftEnter(plugin.Plugin):
    capabilities = ['pwn_shift_enter']
    _hooked_vtes = None
    _orig_register_terminal = None

    def __init__(self):
        plugin.Plugin.__init__(self)
        self._hooked_vtes = set()
        term = Terminator()

        # 1. Hook every terminal that already exists.
        for t in term.terminals:
            self._hook_terminal(t)

        # 2. Hook terminals created *after* the plugin loads (splits, tabs,
        #    new windows) by wrapping Terminator.register_terminal. Only
        #    wrap once even if the plugin is reloaded.
        cls = term.__class__
        if getattr(cls, '_pwn_shift_enter_wrapped', False) is False:
            self._orig_register_terminal = cls.register_terminal

            def register_terminal(inst, terminal, *a, **kw):
                self._orig_register_terminal(inst, terminal, *a, **kw)
                self._hook_terminal(terminal)

            cls.register_terminal = register_terminal
            cls._pwn_shift_enter_wrapped = True

        dbg('PWNShiftEnter: active on %d terminal(s)' % len(self._hooked_vtes))

    def _hook_terminal(self, terminal):
        try:
            vte = terminal.get_vte()
        except Exception as ex:      # pragma: no cover - defensive
            err('PWNShiftEnter: get_vte failed: %s' % ex)
            return
        if vte is None or id(vte) in self._hooked_vtes:
            return
        # connect() (not connect_after) => runs *before* the Vte.Terminal
        # class closure that would encode Return as 0x0D. Terminator's own
        # Terminal.on_keypress handler was connected earlier and returns
        # False for unmapped keys, so it does not swallow our event.
        vte.connect('key-press-event', self._on_key_press)
        self._hooked_vtes.add(id(vte))

    def _on_key_press(self, vte, event):
        if event.keyval not in (Gdk.KEY_Return, Gdk.KEY_KP_Enter,
                                Gdk.KEY_ISO_Enter):
            return False
        state = event.get_state()
        if not state & Gdk.ModifierType.SHIFT_MASK:
            return False
        if state & CONSUME_MODS:
            return False
        try:
            vte.feed_child(S_ENTER_SEQ)
        except TypeError:
            # Older VTE python bindings: feed_child(text, length)
            vte.feed_child(S_ENTER_SEQ, len(S_ENTER_SEQ))
        return True  # stop emission - VTE never sees the raw Return

    def unload(self):
        for terminal in Terminator().terminals:
            try:
                terminal.get_vte().disconnect_by_func(self._on_key_press)
            except Exception:
                pass
        self._hooked_vtes = set()
        if self._orig_register_terminal is not None:
            cls = Terminator().__class__
            cls.register_terminal = self._orig_register_terminal
            cls._pwn_shift_enter_wrapped = False
