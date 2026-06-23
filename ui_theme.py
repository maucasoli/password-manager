import tkinter as tk


class Theme:

    def __init__(self):
        self.fg = "#E5E7EB"
        self.bg = "#1A1D2E"

    def label(self, parent, text, font, fg=None, bg=None, **kwargs):
        if fg is None:
            fg = self.fg

        if bg is None:
            bg = self.bg

        return tk.Label(parent, text=text, font=font, fg=fg, bg=bg, **kwargs)

    def entry(self, parent, fg=None, bg=None, **kwargs):
        if fg is None:
            fg = self.fg

        if bg is None:
            bg = self.bg

        return tk.Entry(parent, fg=fg, bg=bg, **kwargs)

    def button(self, parent, command, text, fg=None, bg=None, **kwargs):
        if fg is None:
            fg = self.fg

        if bg is None:
            bg = self.bg

        btn = tk.Button(
            parent,
            command=command,
            text=text,
            fg=fg,
            bg=bg,
            relief="flat",
            bd=0,
            **kwargs
        )

        btn.bind("<Return>", lambda event: btn.invoke())

        return btn
