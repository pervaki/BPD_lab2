import json
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import re
import hashlib
from datetime import datetime

USER_FILE = 'users.json'
REGISTER_LOG = 'register_log.txt'
OPERATION_LOG = 'operation_log.txt'
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    has_latin = re.search(r'[A-Za-z]', password)
    has_cyrillic = re.search(r'[А-Яа-яІіЇїЄєҐґ]', password)
    has_punctuation = re.search(r'[.,!?;:]', password)
    return has_latin and has_cyrillic and has_punctuation

def load_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "ADMIN": {
                    "password_hash": "",
                    "is_locked": False,
                    "password_restrictions": False
                }
            }, f, ensure_ascii=False, indent=4)
    with open(USER_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

def log_register_action(username, action):
    with open(REGISTER_LOG, 'a', encoding='utf-8') as log:
        log.write(f"{datetime.now()}: {username} {action}\n")

def log_operation_action(username, action):
    with open(OPERATION_LOG, 'a', encoding='utf-8') as log:
        log.write(f"{datetime.now()}: {username} {action}\n")

class LoginApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Система аутентифікації")
        self.master.geometry("300x150")
        self.users = load_users()
        self.attempts = 0
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Ім'я користувача:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.username_entry = tk.Entry(self.master)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky='w')
        tk.Label(self.master, text="Пароль:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')
        tk.Button(self.master, text="Вхід", command=self.login, width=20).grid(row=2, column=0, columnspan=2, pady=20)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if username not in self.users:
            messagebox.showerror("Помилка", "Користувач не знайдений.")
            return

        user = self.users[username]

        if user["is_locked"]:
            messagebox.showerror("Заблоковано", "Ваш обліковий запис заблоковано.")
            return

        if user["password_hash"] == "":
            self.master.withdraw()
            self.set_initial_password(username)
            self.master.deiconify()
            return

        if user["password_hash"] != hash_password(password):
            self.attempts += 1
            remaining = MAX_ATTEMPTS - self.attempts
            if remaining > 0:
                messagebox.showerror("Помилка", f"Неправильний пароль. Залишилось спроб: {remaining}")
            else:
                user["is_locked"] = True
                save_users(self.users)
                log_register_action(username, "заблоковано за перевищення кількості спроб")
                messagebox.showerror("Заблоковано", "Превищено кількість спроб. Обліковий запис заблоковано.")
                self.master.destroy()
            return
        else:
            self.attempts = 0

        log_register_action(username, "успішний вхід")

        if username.upper() == "ADMIN":
            self.master.withdraw()
            admin_window = tk.Toplevel(self.master)
            AdminApp(admin_window, username, self.users, save_users)
        else:
            self.master.withdraw()
            user_window = tk.Toplevel(self.master)
            UserApp(user_window, username, self.users, save_users)

    def set_initial_password(self, username):
        messagebox.showinfo("Первинний вхід", "Необхідно встановити пароль.")
        while True:
            new_password = simpledialog.askstring("Встановити пароль", "Введіть новий пароль:", show="*")
            if new_password is None:
                messagebox.showinfo("Вихід", "Необхідно встановити пароль для входу.")
                self.master.destroy()
                return
            confirm_password = simpledialog.askstring("Підтвердження пароля", "Підтвердіть новий пароль:", show="*")
            if new_password != confirm_password:
                messagebox.showerror("Помилка", "Паролі не співпадають. Спробуйте ще раз.")
                continue
            if self.users[username]["password_restrictions"]:
                if not validate_password(new_password):
                    messagebox.showerror("Помилка",
                                         "Пароль повинен містити латинські літери, кириличні символи та розділові знаки.")
                    continue
            self.users[username]["password_hash"] = hash_password(new_password)
            save_users(self.users)
            log_register_action(username, "встановив новий пароль")
            messagebox.showinfo("Успіх", "Пароль успішно встановлено.")
            break

class AdminApp:
    def __init__(self, master, username, users, save_func):
        self.master = master
        self.master.title("Адміністратор")
        self.master.geometry("600x400")
        self.username = username
        self.users = users
        self.save_func = save_func
        self.create_widgets()

    def create_widgets(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        user_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Користувачі", menu=user_menu)
        user_menu.add_command(label="Додати користувача", command=self.add_user)
        user_menu.add_command(label="Змінити пароль", command=self.change_password)
        user_menu.add_command(label="Блокувати/Розблокувати користувача", command=self.lock_user)
        user_menu.add_command(label="Налаштувати обмеження паролів", command=self.toggle_password_restrictions)
        user_menu.add_separator()
        user_menu.add_command(label="Вийти", command=self.logout)

        self.tree = ttk.Treeview(self.master, columns=("Користувач", "Статус", "Обмеження пароля"), show='headings')
        self.tree.heading("Користувач", text="Користувач")
        self.tree.heading("Статус", text="Статус")
        self.tree.heading("Обмеження пароля", text="Обмеження пароля")
        self.tree.column("Користувач", width=200, anchor='center')
        self.tree.column("Статус", width=150, anchor='center')
        self.tree.column("Обмеження пароля", width=200, anchor='center')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.refresh_user_list()

    def refresh_user_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for user, info in self.users.items():
            status = "Заблоковано" if info["is_locked"] else "Активно"
            restrictions = "Так" if info["password_restrictions"] else "Ні"
            self.tree.insert("", tk.END, values=(user, status, restrictions))

    def add_user(self):
        new_user = simpledialog.askstring("Додати користувача", "Введіть ім'я нового користувача:")
        if new_user:
            new_user = new_user.strip()
            if new_user.upper() == "ADMIN":
                messagebox.showerror("Помилка", "Ім'я ADMIN зарезервоване.")
                return
            if new_user in self.users:
                messagebox.showerror("Помилка", "Користувач вже існує.")
                return
            self.users[new_user] = {
                "password_hash": "",
                "is_locked": False,
                "password_restrictions": True
            }
            self.save_func(self.users)
            self.refresh_user_list()
            log_operation_action(self.username, f"додав користувача {new_user}")
            messagebox.showinfo("Успіх", f"Користувача '{new_user}' додано.")

    def lock_user(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Помилка", "Виберіть користувача зі списку.")
            return
        user = self.tree.item(selected_item)["values"][0]
        if user.upper() == "ADMIN":
            messagebox.showerror("Помилка", "Адміністратора не можна блокувати.")
            return
        current_status = self.users[user]["is_locked"]
        action = "Розблокувати" if current_status else "Заблокувати"
        confirm = messagebox.askyesno("Підтвердження", f"Ви дійсно хочете {action.lower()} користувача '{user}'?")
        if confirm:
            self.users[user]["is_locked"] = not current_status
            self.save_func(self.users)
            self.refresh_user_list()
            log_operation_action(self.username, f"{action.lower()} користувача {user}")
            messagebox.showinfo("Успіх", f"Користувача '{user}' {'заблоковано' if self.users[user]['is_locked'] else 'розблоковано'}.")

    def change_password(self):
        user = simpledialog.askstring("Змінити пароль", "Введіть ім'я користувача:")
        if user is None:
            return
        user = user.strip()
        if user not in self.users:
            messagebox.showerror("Помилка", "Користувач не знайдений.")
            return
        if user.upper() == "ADMIN":
            old_password = simpledialog.askstring("Змінити пароль", "Введіть старий пароль:", show="*")
            if self.users[user]["password_hash"] != hash_password(old_password):
                messagebox.showerror("Помилка", "Неправильний старий пароль.")
                return
        while True:
            new_password = simpledialog.askstring("Змінити пароль", "Введіть новий пароль:", show="*")
            if new_password is None:
                return
            confirm_password = simpledialog.askstring("Підтвердження пароля", "Підтвердіть новий пароль:", show="*")
            if new_password != confirm_password:
                messagebox.showerror("Помилка", "Паролі не співпадають. Спробуйте ще раз.")
                continue
            if self.users[user]["password_restrictions"]:
                if not validate_password(new_password):
                    messagebox.showerror("Помилка", "Пароль повинен містити латинські літери, кириличні символи та розділові знаки.")
                    continue
            self.users[user]["password_hash"] = hash_password(new_password)
            self.save_func(self.users)
            log_operation_action(self.username, f"змінив пароль для користувача {user}")
            messagebox.showinfo("Успіх", f"Пароль користувача '{user}' успішно змінено.")
            break

    def toggle_password_restrictions(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Помилка", "Виберіть користувача зі списку.")
            return
        user = self.tree.item(selected_item)["values"][0]
        if user.upper() == "ADMIN":
            messagebox.showerror("Помилка", "Неможливо змінювати обмеження паролів для ADMIN.")
            return
        current = self.users[user]["password_restrictions"]
        action = "Включити" if not current else "Вимкнути"
        confirm = messagebox.askyesno("Підтвердження", f"Ви дійсно хочете {action.lower()} обмеження паролів для користувача '{user}'?")
        if confirm:
            self.users[user]["password_restrictions"] = not current
            self.save_func(self.users)
            self.refresh_user_list()
            log_operation_action(self.username, f"{action.lower()} обмеження паролів для користувача {user}")
            messagebox.showinfo("Успіх", f"Обмеження паролів для користувача '{user}' {'включено' if self.users[user]['password_restrictions'] else 'вимкнено'}.")

    def logout(self):
        log_register_action(self.username, "вийшов з системи")
        self.master.destroy()
        root.deiconify()

class UserApp:
    def __init__(self, master, username, users, save_func):
        self.master = master
        self.master.title(f"Користувач: {username}")
        self.master.geometry("400x200")
        self.username = username
        self.users = users
        self.save_func = save_func
        self.create_widgets()

    def create_widgets(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        account_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Обліковий запис", menu=account_menu)
        account_menu.add_command(label="Змінити пароль", command=self.change_password)
        account_menu.add_separator()
        account_menu.add_command(label="Вийти", command=self.logout)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Довідка", menu=help_menu)
        help_menu.add_command(label="Про програму", command=self.show_about)

        tk.Label(self.master, text=f"Ласкаво просимо, {self.username}!", font=("Arial", 14)).pack(padx=20, pady=20)

    def change_password(self):
        while True:
            new_password = simpledialog.askstring("Змінити пароль", "Введіть новий пароль:", show="*")
            if new_password is None:
                return
            confirm_password = simpledialog.askstring("Підтвердження пароля", "Підтвердіть новий пароль:", show="*")
            if new_password != confirm_password:
                messagebox.showerror("Помилка", "Паролі не співпадають. Спробуйте ще раз.")
                continue
            if self.users[self.username]["password_restrictions"]:
                if not validate_password(new_password):
                    messagebox.showerror("Помилка", "Пароль повинен містити латинські літери, кириличні символи та розділові знаки.")
                    continue
            self.users[self.username]["password_hash"] = hash_password(new_password)
            self.save_func(self.users)
            log_operation_action(self.username, "змінив свій пароль")
            messagebox.showinfo("Успіх", "Пароль успішно змінено.")
            break

    def logout(self):
        log_register_action(self.username, "вийшов з системи")
        self.master.destroy()
        root.deiconify()

    def show_about(self):
        messagebox.showinfo("Про програму", "Виконав: Первак Ілля ІПЗ-21-1\nІнд. завдання №11: Наявність латинських букв, символів кирилиці і розділових знаків.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
