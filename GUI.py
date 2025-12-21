from tkinter import *
from tkinter import ttk
import tkinter as tk
from tkinter import messagebox
import ctypes
import os
import ast

PASSWORD_FILE = "passwords.txt"
DELIMITER = " | " 

c_lib = None
try:
    dll_name = "manager.dll"
    dll_path = os.path.join(os.getcwd(), dll_name)
    c_lib = ctypes.CDLL(dll_path)
    c_lib.check_master_key.argtypes = [ctypes.c_char_p]
    c_lib.check_master_key.restype = ctypes.c_int
    c_lib.randomPasswordGeneration.argtypes = [ctypes.c_int, ctypes.c_char_p]

    # --- Добавление определений для блочного шифрования ---
    # Создаем типы для массивов: 2 элемента для блока и 4 для ключа
    uint32_2 = ctypes.c_uint32 * 2
    uint32_4 = ctypes.c_uint32 * 4
    
    # Регистрируем аргументы функций из DLL
    c_lib.encrypt_block.argtypes = [ctypes.POINTER(uint32_2), ctypes.POINTER(uint32_4)]
    c_lib.decrypt_block.argtypes = [ctypes.POINTER(uint32_2), ctypes.POINTER(uint32_4)]

    print("C in working now (manager.dll). Block encryption added.")
except Exception as e:
    print(f"Error of C: {e}")
    messagebox.showerror("Error", "Not founded manager.dll!")

# --- Вспомогательные функции для работы с блоками ---

def tea_encrypt_string(plain_text):
    """Шифрует строку, разбивая её на блоки по 8 байт (2x32 бит)."""
    if not c_lib: return plain_text
    
    # Ключ (должен совпадать с тем, что в C или генерироваться из мастер-ключа)
    key = uint32_4(0x45415449, 0x4E475041, 0x5353574F, 0x52445321) 
    
    data = plain_text.encode('utf-8')
    # Дополняем данные до кратности 8 байтам (PKCS7-like padding)
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len] * pad_len)
    
    result = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        v0 = int.from_bytes(chunk[0:4], 'little')
        v1 = int.from_bytes(chunk[4:8], 'little')
        block = uint32_2(v0, v1)
        c_lib.encrypt_block(ctypes.byref(block), ctypes.byref(key))
        # Сохраняем как кортеж чисел для корректного сохранения в файл через ваш DELIMITER
        result.append((block[0], block[1]))
    return str(result)

def tea_decrypt_string(encrypted_str):
    """Дешифрует строку, представленную в виде списка кортежей (блоков)."""
    if not c_lib: return encrypted_str
    
    key = uint32_4(0x45415449, 0x4E475041, 0x5353574F, 0x52445321)
    
    try:
        blocks = ast.literal_eval(encrypted_str)
        decrypted_bytes = bytearray()
        
        for v0, v1 in blocks:
            block = uint32_2(v0, v1)
            c_lib.decrypt_block(ctypes.byref(block), ctypes.byref(key))
            decrypted_bytes.extend(block[0].to_bytes(4, 'little'))
            decrypted_bytes.extend(block[1].to_bytes(4, 'little'))
            
        # Убираем padding (последний байт указывает количество дополненных байт)
        pad_len = decrypted_bytes[-1]
        if 0 < pad_len <= 8:
            decrypted_bytes = decrypted_bytes[:-pad_len]
            
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return "Decryption Error"

MAIN_BG = "#212121"
FRAME_BG = "#2B2B2B"
TEXT_COLOR = "#F0F0F0"
INPUT_BG = "#424242"
SUCCESS_COLOR = "#9B59B6"
DANGER_COLOR = "#E74C3C"

window = Tk()
window.withdraw()
key_var = tk.StringVar()
ask_var = tk.StringVar()

def load_passwords(treev):
    """Loading encrypted data from file to Treeview."""
    if not os.path.exists(PASSWORD_FILE): return

    try:
        with open(PASSWORD_FILE, "r") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line: continue
                parts = line.split(DELIMITER)
                if len(parts) >= 3:
                    tag = "Odd" if i % 2 == 0 else "Even"
                    treev.insert("", "end", values=tuple(parts), tags=(tag,))
    except Exception as e:
        messagebox.showerror("Error", f"Cannot load data: {e}")

def save_passwords(treev):
    """Save data"""
    try:
        data_to_save = [DELIMITER.join(treev.item(item, "values")) for item in treev.get_children()]
        with open(PASSWORD_FILE, "w") as f:
            f.write("\n".join(data_to_save))
        print(f"Data saved in {PASSWORD_FILE}")
    except Exception as e:
        messagebox.showerror("Error", f"Not able to save: {e}")

def closing(win):
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        win.destroy()
        if win == window: exit()

def login():
    login_window = Toplevel(window)
    login_window.title("Password Keeper")
    login_window.geometry("300x200")
    login_window.configure(bg=MAIN_BG)

    login_window.grid_rowconfigure(0, weight=1)
    login_window.grid_rowconfigure(1, weight=1)
    login_window.grid_rowconfigure(2, weight=1)
    login_window.grid_columnconfigure(0, weight=1)
    login_window.grid_columnconfigure(1, weight=1)
    login_window.grid_columnconfigure(2, weight=1)

    lbl = Label(login_window,
                text="Welcome to Password keeper.\nClick login to continue",
                font=("Arial", 10),
                bg=MAIN_BG, fg=TEXT_COLOR)
    lbl.grid(row=0, column=0, columnspan=3)

    btn_login = Button(login_window,
                        text="Login",
                        width=20,
                        bg=SUCCESS_COLOR,
                        fg=TEXT_COLOR)
    btn_login.grid(row=1, column=1)

    entry_key = Entry(login_window,
                      textvariable=key_var,
                      font=('Arial', 12),
                      show='*',
                      bg=INPUT_BG,
                      fg=TEXT_COLOR)

    btn_submit = Button(login_window,
                             text="Submit",
                             bg=SUCCESS_COLOR,
                             fg=TEXT_COLOR,
                             width=20,
                             command=lambda: submit(login_window))
    
    entry_key.bind('<Return>', lambda event: submit(login_window))
    
    def show_key_input():
        btn_login.grid_forget()
        entry_key.grid(row=1, column=0, columnspan=3, pady=10)
        btn_submit.grid(row=2, column=1)
        lbl.config(text="Enter your master key:")
        entry_key.focus_set() 

    btn_login.config(command=show_key_input)
    login_window.protocol("WM_DELETE_WINDOW", lambda: closing(login_window))

def submit(login_window):
    masterKey = key_var.get()
    key_var.set("")
    if c_lib:
        key_buffer = ctypes.create_string_buffer(masterKey.encode('utf-8'))
        is_valid = c_lib.check_master_key(key_buffer)
        if is_valid == 1:
            login_window.destroy()
            mainApp()
            return 
        else:
            messagebox.showerror("Error", "Wrong master-key!")
            return 
    if not c_lib:
        messagebox.showerror("Error", "DLL is not loaded.")
        return
    login_window.destroy()
    mainApp()

def mainApp():
    main_window = Toplevel(window)
    main_window.title("Menu")
    main_window.geometry("900x600")
    main_window.configure(bg=FRAME_BG)
    sidebar = Frame(main_window, bg=FRAME_BG, width=150)
    sidebar.pack(side=LEFT, fill=Y)
    
    def add_info():
        info_window = Toplevel(main_window)
        info_window.title("Add Password")
        info_window.geometry("400x350")
        info_window.configure(bg=FRAME_BG)
        info_frame = Frame(info_window, bg=FRAME_BG, padx=20, pady=20)
        info_frame.pack(expand=True, fill=BOTH)
        
        lbl_website = Label(info_frame, text="Website:", bg=FRAME_BG, fg=TEXT_COLOR)
        lbl_website.grid(row=0, column=0, sticky='w', pady=5)
        entry_website = Entry(info_frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_website.grid(row=0, column=1, pady=5)

        lbl_email = Label(info_frame, text="Email/Login:", bg=FRAME_BG, fg=TEXT_COLOR)
        lbl_email.grid(row=1, column=0, sticky='w', pady=5)
        entry_email = Entry(info_frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_email.grid(row=1, column=1, pady=5)

        lbl_password = Label(info_frame, text="Password:", bg=FRAME_BG, fg=TEXT_COLOR)
        lbl_password.grid(row=2, column=0, sticky='w', pady=5)
        entry_password = Entry(info_frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_password.grid(row=2, column=1, pady=5)

        lbl_category = Label(info_frame, text="Category:", bg=FRAME_BG, fg=TEXT_COLOR)
        lbl_category.grid(row=3, column=0, sticky='w', pady=5)
        entry_category = Entry(info_frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_category.grid(row=3, column=1, pady=5)

        def save_and_encrypt():
            site = entry_website.get()
            email = entry_email.get()
            password = entry_password.get()
            category = entry_category.get()

            if not c_lib:
                messagebox.showerror("Error", "DLL doesnt work.")
                return

            # ПРИМЕНЕНИЕ БЛОЧНОГО ШИФРОВАНИЯ
            encrypted_data = tea_encrypt_string(password)

            i = len(treev.get_children())
            tag = "Odd" if i % 2 == 0 else "Even"
            treev.insert("", "end", values=(site, email, encrypted_data, category), tags=(tag,))
            save_passwords(treev)
            info_window.destroy()
        
        btn_submit_info = Button(info_frame, text="Add Password", bg=SUCCESS_COLOR, fg=TEXT_COLOR, 
                                 width=20, command=save_and_encrypt) 
        btn_submit_info.grid(row=4, column=0, columnspan=2, pady=15)
        
    def edit_info():
        edited_info = treev.selection()
        if not edited_info:
            messagebox.showwarning("Warning", "Please select an item to delete.")
            return
        item = edited_info[0]
        values = treev.item(item, "values")

        edit_window = Toplevel(main_window)
        edit_window.title("Edit")
        edit_window.geometry("400x350")
        edit_window.configure(bg=FRAME_BG)

        frame = Frame(edit_window, bg=FRAME_BG, padx=20, pady=20)
        frame.pack(expand=True, fill=BOTH)
        
        Label(frame, text="Website:", bg=FRAME_BG, fg=TEXT_COLOR).grid(row=0, column=0, sticky="w", pady=5)
        entry_website = Entry(frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_website.grid(row=0, column=1, pady=5)
        entry_website.insert(0, values[0])

        Label(frame, text="Email/Login:", bg=FRAME_BG, fg=TEXT_COLOR).grid(row=1, column=0, sticky="w", pady=5)
        entry_email = Entry(frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_email.grid(row=1, column=1, pady=5)
        entry_email.insert(0, values[1])

        Label(frame, text="Password:", bg=FRAME_BG, fg=TEXT_COLOR).grid(row=2, column=0, sticky="w", pady=5)
        entry_password = Entry(frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_password.grid(row=2, column=1, pady=5)
        entry_password.insert(0, values[2])

        Label(frame, text="Category:", bg=FRAME_BG, fg=TEXT_COLOR).grid(row=3, column=0, sticky="w", pady=5)
        entry_category = Entry(frame, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_category.grid(row=3, column=1, pady=5)
        entry_category.insert(0, values[3] if len(values) > 3 else "")

        def save_changes():
            new_w = entry_website.get()
            new_e = entry_email.get()
            new_p = entry_password.get()
            new_c = entry_category.get()
            treev.item(item, values=(new_w, new_e, new_p, new_c))
            save_passwords(treev) 
            edit_window.destroy()

        Button(frame, text="Save changes", bg=SUCCESS_COLOR, fg=TEXT_COLOR,
            width=20, command=save_changes).grid(row=4, column=0, columnspan=2, pady=15)

    def delete_info():
        selected_info = treev.selection()
        if not selected_info:
            messagebox.showwarning("Warning", "Please select an item to delete.")
            return
        confirm = messagebox.askyesno("Delete password", "Are you sure you want to delete the selected information?")
        if confirm:
            treev.delete(selected_info)
            save_passwords(treev) 

    def search_info():
        search_window = Toplevel(main_window)
        search_window.title("Search")
        search_window.geometry("300x120")
        search_window.configure(bg=FRAME_BG)
        entry_info = Entry(search_window, bg=INPUT_BG, fg=TEXT_COLOR, width=30)
        entry_info.grid(column=0, row=0, padx=10, pady=10, columnspan=2)

        def run_search():
            search_text = entry_info.get().lower().strip()
            if not search_text:
                messagebox.showwarning("Warning", "Enter text to search!")
                return
            found = False
            for item in treev.get_children():
                values = treev.item(item, "values")
                if any(search_text in str(v).lower() for v in values):
                    treev.selection_set(item)
                    treev.see(item)
                    found = True
                    break
            if not found:
                messagebox.showinfo("Not found", "No matching information.")

        info_btn = Button(search_window, text="Search", bg=SUCCESS_COLOR, fg=TEXT_COLOR,
                          width=10, command=run_search)
        info_btn.grid(column=0, row=1, pady=10, columnspan=2)

    def view_decrypted_password():
        selected_item = treev.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an item to view the password.")
            return

        item = selected_item[0]
        values = treev.item(item, "values")
        encrypted_password_str = values[2] 

        if not c_lib:
            messagebox.showerror("Error", "DLL is not loaded.")
            return

        # ПРИМЕНЕНИЕ БЛОЧНОГО ДЕШИФРОВАНИЯ
        decrypted_password = tea_decrypt_string(encrypted_password_str)

        view_window = Toplevel(main_window)
        view_window.title("Decrypted Password")
        view_window.geometry("450x220")
        view_window.configure(bg=FRAME_BG)
        
        view_frame = Frame(view_window, bg=FRAME_BG, padx=20, pady=20)
        view_frame.pack(expand=True, fill=BOTH)
        view_frame.columnconfigure(1, weight=1)

        Label(view_frame, text="Website:", bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12)).grid(row=0, column=0, sticky='w', padx=5, pady=2)
        Label(view_frame, text=values[0], bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12, "bold")).grid(row=0, column=1, sticky='w', pady=2)

        Label(view_frame, text="Login:", bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12)).grid(row=1, column=0, sticky='w', padx=5, pady=2)
        Label(view_frame, text=values[1], bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12, "bold")).grid(row=1, column=1, sticky='w', pady=2)

        Label(view_frame, text="Password:", bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12)).grid(row=2, column=0, sticky='w', padx=5, pady=2)
        Label(view_frame, text=decrypted_password, bg=FRAME_BG, fg=SUCCESS_COLOR, font=("Arial", 14, "bold")).grid(row=2, column=1, sticky='w', pady=10)

        Label(view_frame, text="Category:", bg=FRAME_BG, fg=TEXT_COLOR, font=("Arial", 12)).grid(row=3, column=0, sticky='w', padx=5, pady=2)
        Label(view_frame, text=values[3], bg=FRAME_BG, fg=SUCCESS_COLOR, font=("Arial", 14, "bold")).grid(row=3, column=1, sticky='w', pady=10)

        Button(view_frame, text="Close", bg=DANGER_COLOR, fg=TEXT_COLOR, width=10, command=view_window.destroy).grid(row=4, column=0, columnspan=2, pady=10)

    def generate_pass():
        generate_window = Toplevel(main_window)
        generate_window.title("Generate Password")
        generate_window.geometry("350x120")
        generate_window.configure(bg=FRAME_BG)
        generate_info = Entry(generate_window, bg=INPUT_BG, fg=TEXT_COLOR, readonlybackground=INPUT_BG,
                              disabledforeground=TEXT_COLOR, width=25, font=("Consolas", 11), state="readonly")
        generate_info.grid(column=0, row=0, padx=10, pady=20)

        def on_generate_click():
            if not c_lib:
                messagebox.showerror("Error", "DLL not found")
                return
            length = 15
            buf = ctypes.create_string_buffer(length + 1)
            c_lib.randomPasswordGeneration(length, buf)
            pwd_result = buf.value.decode("utf-8")
            generate_info.config(state="normal")
            generate_info.delete(0, END)
            generate_info.insert(0, pwd_result)
            generate_info.config(state="readonly")

        btn_gen_inside = Button(generate_window, text="Generate", bg=SUCCESS_COLOR, fg=TEXT_COLOR,
                                width=10, command=on_generate_click)
        btn_gen_inside.grid(row=0, column=1, padx=5)

    btn_add = Button(sidebar, text="Add", bg=SUCCESS_COLOR, fg=TEXT_COLOR, width=20, command=add_info)
    btn_add.grid(row=0,column=0)
    btn_edit = Button(sidebar,text="Edit",bg=SUCCESS_COLOR,fg=TEXT_COLOR,width=20,command=edit_info)
    btn_edit.grid(row=1,column=0)
    btn_delete = Button(sidebar,text="Delete",bg=SUCCESS_COLOR,fg=TEXT_COLOR,width=20,command=delete_info)
    btn_delete.grid(row=2,column=0)
    btn_view = Button(sidebar,text="View Password",bg=SUCCESS_COLOR,fg=TEXT_COLOR,width=20,command=view_decrypted_password)
    btn_view.grid(row=3,column=0)
    btn_search = Button(sidebar,text="Search",bg=SUCCESS_COLOR,fg=TEXT_COLOR,width=20,command=search_info)
    btn_search.grid(row=4,column=0)
    btn_generate = Button(sidebar,text="Generate Password",bg=SUCCESS_COLOR,fg=TEXT_COLOR,width=20,command=generate_pass)
    btn_generate.grid(row=5,column=0)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=INPUT_BG, foreground=TEXT_COLOR, rowheight=30, fieldbackground=FRAME_BG, font=("Arial", 10))
    style.map("Treeview", background=[('selected', SUCCESS_COLOR)], foreground=[('selected', TEXT_COLOR)])

    treev = ttk.Treeview(main_window, selectmode='browse')
    treev.pack(side='left', fill="both", expand=True)
    verscrlbar = ttk.Scrollbar(main_window, orient="vertical", command=treev.yview)
    verscrlbar.pack(side='right', fill='y')
    treev.configure(yscrollcommand=verscrlbar.set)
    treev["columns"] = ("1", "2", "3","4")
    treev["show"] = "headings"
    treev.column("1", width=200, anchor='w')
    treev.column("2", width=200, anchor='w')
    treev.column("3", width=150, anchor='w')
    treev.column("4", width=150,anchor='w' )
    treev.heading("1", text="Website")
    treev.heading("2", text="Email / Login")
    treev.heading("3", text="Password (Encrypted)") 
    treev.heading("4", text="Category")
    treev.tag_configure("Odd", background=FRAME_BG, foreground=TEXT_COLOR)
    treev.tag_configure("Even", background=INPUT_BG, foreground=TEXT_COLOR)

    load_passwords(treev)
    main_window.protocol("WM_DELETE_WINDOW", lambda: closing(main_window))

login()
window.mainloop()