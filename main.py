import os
import math
import secrets
import random
import itertools
from itertools import chain
import threading
import pyperclip

import tkinter as tk
from tkinter import font
from tkinter import scrolledtext
from tkinter import messagebox
from PIL import Image, ImageTk



# generate 16 byte encryption key
class generate_key:
    def __init__(self, k = False):
        if k:
            if len(k) == 22:
                key = k
            else:
                raise ValueError("Incorrect key length!")
        else:
            key = secrets.token_urlsafe(16)

        # assign the key
        self.key = key

        # key in unicode code points (decimal)
        code_point = [ord(char) for char in key]

        # some calculations for making the key hard to read
        self.substitution = ((code_point[-1] - code_point[0]) % 22) * code_point[-2] + code_point[13]
        self.route = int((((code_point[10] % 22)**code_point[self.substitution%22]) % 22) + 4)
        self.reverse = code_point[5] > code_point[6]
        self.addition = int(math.floor(sum(code_point)/len(code_point))/5)
        self.rounds = int(abs(math.ceil(math.sin(code_point[9])*code_point[4]))/3)+5
        self.order = code_point[15] + 9 < code_point[18] - 5

# encode input text to unicode code points (decimal)
def encode(plaintext):
    return [ord(char) for char in plaintext]

# decode ciphertext from unicode code points to unicode string
def decode(encoded): 
    return "".join([chr(char) for char in encoded])

def encrypt(plaintext, key, substitution, route, reverse, addition, rounds, order):
    if len(plaintext) == 0:
        return ""

    # substitution cipher
    # using modular function to wrap around the shift of characters
    # max code point value of UTF-8 character is 1114111
    substitution_text = list(map(lambda x: (x + substitution)%1114112, plaintext))

    # route cipher
    route_text = []

    while len(substitution_text) != 0:
        route_text.append(substitution_text[:route])
        substitution_text = substitution_text[route:]

    # * operator is used here to unpack an iterable into arguments in a function call
    route_text = list(itertools.zip_longest(*route_text, fillvalue=(95+substitution)%1114112))
    route_text = list(chain.from_iterable(route_text))

    # permutation cipher
    def permutation_cipher(plaintext, key, reverse):
        perm_text = []
        while len(plaintext) != 0:
            perm_text.append(plaintext[:22])
            plaintext = plaintext[22:]

        for i in range(len(perm_text)):
            indexed = list(zip(perm_text[i], key))
            indexed.sort(key=lambda x: x[1], reverse=not reverse)
            perm_text[i] = [x for x, y in indexed]

        return list(chain.from_iterable(perm_text))

    ciphertext = permutation_cipher(route_text, key, reverse)

    for _ in range(rounds-1):
        ciphertext = permutation_cipher(ciphertext, key, reverse)

    # additional measures

    # random addition
    for i in range(addition, len(ciphertext), addition):
        ciphertext.insert(i, random.randint(0, 1114111))

    # order of reading
    if order == True:
        ciphertext = [x for x in reversed(ciphertext)]
        
    return ciphertext

def decrypt(ciphertext, key, substitution, route, reverse, addition, rounds, order):
    if len(ciphertext) == 0:
        return ""

    # additional measures
    
    # order of reading
    if order == True:
        ciphertext = [x for x in reversed(ciphertext)]

    # random addition
    count = 0
    remove = addition
    while remove < len(ciphertext):
        ciphertext.pop(remove-count)
        remove += addition
        count += 1
    
    # permutation cipher
    def permutation_cipher(ciphertext, key, reverse):
        perm_text = []
        while len(ciphertext) != 0:
            perm_text.append(ciphertext[:22])
            ciphertext = ciphertext[22:]

        for i in range(len(perm_text)):
            unsorted_key = encode(key[:len(perm_text[i])])
            sorted_key = sorted(unsorted_key, reverse=not reverse)
            key_indices = []

            for k in list(dict.fromkeys(sorted_key)):
                for x, y in enumerate(unsorted_key):
                    if k == y:
                        key_indices.append(x)

            indexed = list(zip(perm_text[i], key_indices))
            indexed.sort(key=lambda x: x[1])
            perm_text[i] = [x[0] for x in indexed]

        return list(chain.from_iterable(perm_text))

    for _ in range(rounds):
        ciphertext = permutation_cipher(ciphertext, key, reverse)

    # route cipher
    rows = int(len(ciphertext)/route)
    route_text = []

    if rows == 0:
        rows = 1

    while len(ciphertext) != 0:
        route_text.append(ciphertext[:rows])
        ciphertext = ciphertext[rows:]

    route_text = list(zip(*route_text))
    route_text = list(chain.from_iterable(route_text))

    # remove fill characters "_" used in route cipher
    while route_text[-1] == (95+substitution)%1114112:
        route_text.pop(-1)

    # subtitution cipher
    ciphertext = list(map(lambda x: (x - substitution)%1114112, route_text))  

    return ciphertext



# GUI using Tkinter
class MainApplication(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)

        WIDTH = 600
        HEIGHT = 400

        # master config (tk.Tk)
        # self.master.maxsize(WIDTH, HEIGHT)
        self.master.resizable(False, False)
        self.master.title("TroyIV")

        # center and pack() MainApplication window
        self.center_window(WIDTH, HEIGHT)
        self.pack()

        # local directory
        local = os.getcwd()

        # app icon
        icon = Image.open(local+"/resources/window app icon.png")
        icon.thumbnail((16, 16))
        self.icon = ImageTk.PhotoImage(icon)
        self.master.iconphoto(False, self.icon)
        
        # images
        background = Image.open(local+"/resources/background image.jpg")

        copy_icon = Image.open(local+"/resources/copy icon.png")
        copy_icon.thumbnail((24, 24))
        self.copy_icon = ImageTk.PhotoImage(copy_icon)

        settings_icon = Image.open(local+"/resources/settings icon.png")
        settings_icon.thumbnail((24, 20))
        self.settings_icon = ImageTk.PhotoImage(settings_icon)

        info_icon = Image.open(local+"/resources/info icon.png")
        info_icon.thumbnail((26, 26))
        self.info_icon = ImageTk.PhotoImage(info_icon)

        key_icon = Image.open(local+"/resources/key icon.png")
        key_icon.thumbnail((36, 26))
        self.key_icon = ImageTk.PhotoImage(key_icon)

        # build widgets
        self.background(background)
        self.main_widgets(self.copy_icon, self.key_icon)
        self.other_widgets(local, self.settings_icon, self.info_icon)

    def center_window(self, width=600, height=400):
        screen_width = self.winfo_screenwidth()
        scren_height = self.winfo_screenheight()

        # center of the screen
        x = screen_width/2 - width/2
        y = scren_height/2 - height/2

        self.master.geometry(f"{width}x{height}+{int(x)}+{int(y)}")

        # older string format alternatives
        # self.master.geometry('%dx%d+%d+%d' % (width, height, x, y))
        # self.master.geometry("{}x{}+{}+{}".format(width, height, int(x), int(y)))

    def background(self, background):
        self.background_image = ImageTk.PhotoImage(background)
        self.background = tk.Label(self, image=self.background_image)
        self.background.pack()

    def main_widgets(self, copy_icon, key_icon):
        # widgets for plaintext
        self.plaintext_frame = tk.Frame(self, bg="#cccccc")
        self.plaintext_frame.place(relx=0.05, rely=0.08, relwidth=0.5, relheight=0.32, anchor="nw")
        self.plaintext = scrolledtext.ScrolledText(self.plaintext_frame, cursor="arrow", font=("Times New Roman", 12), 
                                                    wrap="word", padx=5, pady=5, bd=0)
        self.plaintext.pack(padx=2.5, pady=2)
        self.encrypt_button = tk.Button(self.plaintext, bg="white", font=("Arial Rounded MT Bold", 9), text="Encrypt",    # below we need to use end-1c as ending index because text automatically adds newline \n to get method
                                        relief="flat", cursor="hand2", command=lambda: self.initialize_encryption(self.key_text.get(), self.plaintext.get("1.0", "end-1c"), self.ciphertext))
        self.encrypt_button.place(relx=0.88, rely=1, relwidth=0.2, relheight=0.2, anchor="se")
        self.plaintext_copy = tk.Button(self.plaintext, bg="white", relief="flat", image=copy_icon, cursor="hand2", command=lambda: pyperclip.copy(self.plaintext.get("1.0", "end-1c")))
        self.plaintext_copy.place(relx=1, rely=1, relwidth=0.1, relheight=0.2, anchor="se")

        # widgets for ciphertext
        self.ciphertext_frame = tk.Frame(self, bg="#cccccc")
        self.ciphertext_frame.place(relx=0.05, rely=0.42, relwidth=0.5, relheight=0.32, anchor="nw")
        self.ciphertext = scrolledtext.ScrolledText(self.ciphertext_frame, cursor="arrow", font=("Avenir Next LT Pro", 10), 
                                                    wrap="word", padx=5, pady=5, bd=0)
        self.ciphertext.pack(padx=2.5, pady=2)
        self.decrypt_button = tk.Button(self.ciphertext, bg="white", font=("Arial Rounded MT Bold", 9), text="Decrypt",
                                        relief="flat", cursor="hand2", command=lambda: self.initialize_decryption(self.key_text.get(), self.ciphertext.get("1.0", "end-1c"), self.plaintext))
        self.decrypt_button.place(relx=0.88, rely=1, relwidth=0.2, relheight=0.2, anchor="se")
        self.ciphertext_copy = tk.Button(self.ciphertext, bg="white", relief="flat", image=copy_icon, cursor="hand2", command=lambda: pyperclip.copy(self.ciphertext.get("1.0", "end-1c")))
        self.ciphertext_copy.place(relx=1, rely=1, relwidth=0.1, relheight=0.2, anchor="se")

        # widgets for key
        self.key_frame = tk.Frame(self, bg="#cccccc")
        self.key_frame.place(relx=0.5, rely=0.85, relwidth=0.6, relheight=0.08, anchor="c")

        self.key = tk.Label(self.key_frame, bg="white", image=key_icon)
        self.key.place(relx=0.005, rely=0.5, relwidth=0.08, relheight=0.88, anchor="w")

        self.key_text = tk.Entry(self.key_frame, font=("Bahnschrift", 10), relief="flat")
        self.key_text.place(relx=0.092, rely=0.5, relwidth=0.6, relheight=0.88, anchor="w")

        self.key_button = tk.Button(self.key_frame, bg="white", font=("Arial Rounded MT Bold", 10), relief="flat", text="Generate key", cursor="hand2", command=lambda: self.generate_key())
        self.key_button.place(relx=0.698, rely=0.5, relwidth=0.296, relheight=0.88, anchor="w")

    def other_widgets(self, local, settings, info):
        # version
        self.version = tk.Label(self, text="version 1.0", font=("Bahnschrift", 10))
        self.version.place(relx=0, rely=1, relwidth=0.12, relheight=0.06, anchor="sw")

        # options & info
        self.palette = tk.Frame(self)
        self.palette.place(relx=1, rely=1, relwidth=0.08, relheight=0.06, anchor="se")

        self.settings = tk.Button(self.palette, bg="white", relief="flat", image=settings, cursor="hand2", command=lambda: self.open_settings(settings))
        self.settings.place(relx=0.5, rely=0, relwidth=0.5, relheight=1, anchor="nw")

        self.info = tk.Button(self.palette, bg="white", relief="flat", image=info, cursor="hand2", command=lambda: self.open_info(info))
        self.info.place(relx=0, rely=0, relwidth=0.5, relheight=1, anchor="nw")

    def generate_key(self):
        self.generated_key = generate_key()
        self.key_text.delete(0, tk.END)
        self.key_text.insert(tk.INSERT, self.generated_key.key)

    # creating a separate thread for encryption (in case of performance issues)
    def initialize_encryption(self, key, plaintext, ciphertext):
        thread = threading.Thread(target=self.encryption, args=(key, plaintext, ciphertext))
        thread.start()
    
    def encryption(self, key, plaintext, ciphertext):
        if len(key) == 0:
            self.error_message("Please enter a key!")
            return
        try:
            key = generate_key(key)
            encrypted = encrypt(encode(plaintext), key.key, key.substitution, key.route, key.reverse, key.addition, key.rounds, key.order)
        except ValueError as err:
            self.error_message(err)
            return
        except:
            self.error_message("Invalid key!")
            return

        ciphertext.delete("1.0", tk.END)
        ciphertext.insert("1.0", decode(encrypted))
    
    # creating a separate thread for decryption (in case of performance issues)
    def initialize_decryption(self, key, ciphertext, plaintext):
        thread = threading.Thread(target=self.decryption, args=(key, ciphertext, plaintext))
        thread.start()

    def decryption(self, key, ciphertext, plaintext):
        if len(key) == 0:
            self.error_message("Please enter a key!")
            return
        try:
            key = generate_key(key)
            decrypted = decrypt(encode(ciphertext), key.key, key.substitution, key.route, key.reverse, key.addition, key.rounds, key.order)
        except ValueError as err:
            self.error_message(err)
            return
        except:
            self.error_message("Invalid key!")
            return

        plaintext.delete("1.0", tk.END)
        plaintext.insert("1.0", decode(decrypted))

    def error_message(self, text):
        self.error = tk.messagebox.showerror(title="Error", message=text, parent=self)

    def open_settings(self, icon):
        pass
        # Work in progress
        # global settings_root

        # try:
        #     if settings_root.state() == "normal":
        #         settings_root.focus()
        # except:
        #     settings_root = tk.Toplevel(self.master)
        #     SettingsWindow(master=settings_root, icon=icon)

    def open_info(self, icon):
        global info_root

        try:
            if info_root.state() == "normal":
                info_root.focus()
        except:
            info_root = tk.Toplevel(self.master)
            InfoWindow(master=info_root, icon=icon)



class SettingsWindow(tk.Frame):
    def __init__(self, master=None, icon=None):
        super().__init__(master)

        WIDTH = 300
        HEIGHT = 200

        self.master.title("Settings")
        self.master.resizable(False, False)
        if icon:
            self.master.iconphoto(False, icon)

        # center and pack() SettingsWindow
        self.center_window(WIDTH, HEIGHT)
        self.pack()

        # to focus on this widget
        self.focus()

        # build widgets
        

    def center_window(self, width=300, height=200):
        screen_width = self.winfo_screenwidth()
        scren_height = self.winfo_screenheight()

        # center of the screen
        x = screen_width/2 - width/2
        y = scren_height/2 - height/2

        self.master.geometry(f"{width}x{height}+{int(x)}+{int(y)}")



class InfoWindow(tk.Frame):
    def __init__(self, master=None, icon=None):
        super().__init__(master)

        WIDTH = 300
        HEIGHT = 320

        self.master.title("About this program")
        self.master.resizable(False, False)
        if icon:
            self.master.iconphoto(False, icon)

        # center and pack() InfoWindow
        self.center_window(WIDTH, HEIGHT)
        self.pack()

        # to focus on this widget
        self.focus()

        # build widgets
        self.create_widgets()

    def create_widgets(self):
        self.info = tk.Text(self.master, font=("Times New Roman", 10), padx=10, pady=2, relief="groove", wrap="word", bd=4,
                            )

        self.info.insert(tk.INSERT, "How to use")
        self.info.insert(tk.INSERT, "\nGenerate your own key. The key will be used to encrypt your text.")
        self.info.insert(tk.INSERT, "\nWarning: You need to use the same exact key to decrypt messages correctly.")
        self.info.insert(tk.INSERT, "\n\nDescription")
        self.info.insert(tk.INSERT, "\nThis encryption program is based on symmetric-key encryption. \nIt is capable of encrypting any character within Unicode UTF-8.")
        self.info.insert(tk.INSERT, "\nTo brute force the 128 bit key it takes ≈9.031059052E+37 combinations.")
        self.info.insert(tk.INSERT, "\nSecurity: slightly better than basic ciphers")
        self.info.insert(tk.INSERT, "\nPossible weaknesses: cryptanalysis")
        self.info.insert(tk.INSERT, "\n\nauthor: NotRareOne")
        self.info.insert(tk.INSERT, "\nversion: 1.0                                    first release: 21.4.2021")

        # tags
        self.info.tag_add("title1", "1.0", "1.end")
        self.info.tag_add("warning", "3.0", "3.end")
        self.info.tag_add("title2", "5.0", "5.end")
        self.info.tag_add("security", "9.0", "9.9")
        self.info.tag_add("weaknesses", "10.0", "10.20")
        self.info.tag_add("footnote1", "12.0", "13.end")

        self.info.tag_config("title1", font=("Bahnschrift", 11), underline=True, spacing3=4)
        self.info.tag_config("warning", font=("Times New Roman", 10, "italic"), foreground="red")
        self.info.tag_config("title2", font=("Bahnschrift", 11), underline=True, spacing3=4)
        self.info.tag_config("security", font=("Times New Roman", 10, "italic"), underline=True)
        self.info.tag_config("weaknesses", font=("Times New Roman", 10, "italic"), underline=True)
        self.info.tag_config("footnote1", font=("Arial Nova Light", 7))

        self.info.config(state="disabled")
        self.info.place(relx=0.5, rely=0.5, relwidth=0.95, relheight=0.95, anchor="c")

    def center_window(self, width=300, height=300):
        screen_width = self.winfo_screenwidth()
        scren_height = self.winfo_screenheight()

        # center of the screen (slightly offset to the right)
        x = screen_width/2 + width*0.8
        y = scren_height/2 - height/2

        self.master.geometry(f"{width}x{height}+{int(x)}+{int(y)}")



def main():
    root = tk.Tk()
    app = MainApplication(master=root)
    app.mainloop()

if __name__ == "__main__":
    main()