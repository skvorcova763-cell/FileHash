import hashlib
import os
import queue
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Hash import MD2
from pygost.gost341194 import GOST341194
from pygost.gost34112012 import GOST34112012

ALGORITHMS = (
    'GOST R 34.11-94', 'GOST R 34.11-2012/256', 'GOST R 34.11-2012/512',
    'SHA', 'SHA1', 'SHA384', 'SHA512', 'MD2', 'MD5'
)

class SHA0:
    """SHA-0 (FIPS PUB 180, 1993), not SHA-1."""
    def __init__(self):
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.buf = b''
        self.length = 0

    def update(self, data):
        self.length += len(data)
        self.buf += data
        while len(self.buf) >= 64:
            self._block(self.buf[:64])
            self.buf = self.buf[64:]

    def _block(self, block):
        mask = 0xffffffff
        w = list(struct.unpack('>16I', block))
        for t in range(16, 80):
            w.append((w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]) & mask)
        a, b, c, d, e = self.h
        for t in range(80):
            if t < 20:
                f, k = (b & c) | ((~b) & d), 0x5A827999
            elif t < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif t < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            temp = (((a << 5) | (a >> 27)) + f + e + k + w[t]) & mask
            a, b, c, d, e = temp, a, ((b << 30) | (b >> 2)) & mask, c, d
        self.h = [(x+y) & mask for x, y in zip(self.h, (a,b,c,d,e))]

    def hexdigest(self):
        other = SHA0()
        other.h = self.h.copy()
        other.buf = self.buf
        other.length = self.length
        bits = other.length * 8
        other.update(b'\x80')
        other.update(b'\x00' * ((56 - len(other.buf)) % 64))
        other.update(struct.pack('>Q', bits & 0xffffffffffffffff))
        return ''.join(f'{x:08x}' for x in other.h)


def new_hash(name):
    if name == 'GOST R 34.11-94':
        return GOST341194()
    if name == 'GOST R 34.11-2012/256':
        return GOST34112012(digest_size=32)
    if name == 'GOST R 34.11-2012/512':
        return GOST34112012(digest_size=64)
    if name == 'SHA':
        return SHA0()
    if name == 'MD2':
        return MD2.new()
    return hashlib.new({'SHA1':'sha1','SHA384':'sha384','SHA512':'sha512','MD5':'md5'}[name])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Хеширование файлов — ГОСТ, SHA, MD')
        self.geometry('790x460')
        self.minsize(680, 430)
        self.path = tk.StringVar()
        self.algorithm = tk.StringVar(value=ALGORITHMS[0])
        self.digest = tk.StringVar()
        self.expected = tk.StringVar()
        self.status = tk.StringVar(value='Выберите файл и алгоритм.')
        self.events = queue.Queue()
        self.busy = False
        self._build()
        self.after(80, self._poll)

    def _build(self):
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='Хеширование и проверка целостности файлов', font=('Segoe UI', 15, 'bold')).pack(anchor='w', pady=(0, 15))
        ttk.Label(outer, text='Файл:').pack(anchor='w')
        line = ttk.Frame(outer)
        line.pack(fill='x', pady=(4, 12))
        ttk.Entry(line, textvariable=self.path).pack(side='left', fill='x', expand=True)
        ttk.Button(line, text='Обзор...', command=self._browse).pack(side='left', padx=(8,0))
        ttk.Label(outer, text='Алгоритм хеширования:').pack(anchor='w')
        combo = ttk.Combobox(outer, textvariable=self.algorithm, values=ALGORITHMS, state='readonly')
        combo.pack(fill='x', pady=(4, 12))
        self.calculate = ttk.Button(outer, text='Вычислить хеш', command=self._start)
        self.calculate.pack(anchor='w', pady=(0, 10))
        self.progress = ttk.Progressbar(outer, mode='determinate', maximum=100)
        self.progress.pack(fill='x', pady=(0, 12))
        ttk.Label(outer, text='Полученный хеш (HEX):').pack(anchor='w')
        ttk.Entry(outer, textvariable=self.digest, state='readonly').pack(fill='x', pady=(4, 6))
        buttons = ttk.Frame(outer)
        buttons.pack(anchor='w', pady=(0, 13))
        ttk.Button(buttons, text='Копировать', command=self._copy).pack(side='left')
        ttk.Button(buttons, text='Сохранить в TXT', command=self._save).pack(side='left', padx=8)
        ttk.Label(outer, text='Эталонный хеш для сравнения:').pack(anchor='w')
        ttk.Entry(outer, textvariable=self.expected).pack(fill='x', pady=(4, 7))
        ttk.Button(outer, text='Сравнить хеши', command=self._compare).pack(anchor='w')
        ttk.Label(outer, textvariable=self.status, foreground='#24618a', wraplength=730).pack(anchor='w', pady=(15, 0))

    def _browse(self):
        path = filedialog.askopenfilename(title='Выберите файл')
        if path:
            self.path.set(path)
            self.digest.set('')
            self.progress['value'] = 0

    def _start(self):
        path = self.path.get().strip().strip('"')
        if self.busy:
            return
        if not os.path.isfile(path):
            messagebox.showerror('Ошибка', 'Выберите существующий файл.')
            return
        self.busy = True
        self.calculate.configure(state='disabled')
        self.digest.set('')
        self.progress['value'] = 0
        self.status.set('Вычисление...')
        threading.Thread(target=self._worker, args=(path, self.algorithm.get()), daemon=True).start()

    def _worker(self, path, algorithm):
        try:
            h = new_hash(algorithm)
            size = os.path.getsize(path)
            done = 0
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
                    done += len(chunk)
                    self.events.put(('progress', 100 * done / size if size else 100))
            self.events.put(('done', h.hexdigest()))
        except Exception as exc:
            self.events.put(('error', str(exc)))

    def _poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'progress':
                    self.progress['value'] = value
                elif kind == 'done':
                    self.digest.set(value)
                    self.progress['value'] = 100
                    self.status.set(f'Готово. Алгоритм: {self.algorithm.get()}. Длина: {len(value)*4} бит.')
                    self.busy = False
                    self.calculate.configure(state='normal')
                elif kind == 'error':
                    self.status.set('Ошибка вычисления.')
                    self.busy = False
                    self.calculate.configure(state='normal')
                    messagebox.showerror('Ошибка', value)
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _copy(self):
        if self.digest.get():
            self.clipboard_clear()
            self.clipboard_append(self.digest.get())
            self.status.set('Хеш скопирован в буфер обмена.')

    def _save(self):
        if not self.digest.get():
            messagebox.showinfo('Нет результата', 'Сначала вычислите хеш.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Текстовые файлы','*.txt')])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f'Файл: {self.path.get()}\nАлгоритм: {self.algorithm.get()}\nХеш: {self.digest.get()}\n')
                self.status.set('Результат сохранён.')
            except OSError as exc:
                messagebox.showerror('Ошибка сохранения', str(exc))

    def _compare(self):
        if not self.digest.get():
            messagebox.showinfo('Нет результата', 'Сначала вычислите хеш.')
            return
        expected = ''.join(self.expected.get().split()).lower()
        if len(expected) != len(self.digest.get()) or any(c not in '0123456789abcdef' for c in expected):
            messagebox.showwarning('Неверный хеш', 'Введите эталонный хеш в HEX соответствующей длины.')
            return
        if expected == self.digest.get().lower():
            messagebox.showinfo('Проверка', 'Хеши совпадают. Целостность подтверждена относительно эталона.')
        else:
            messagebox.showwarning('Проверка', 'Хеши НЕ совпадают!')

if __name__ == '__main__':
    App().mainloop()
