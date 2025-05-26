import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from PIL import Image, ImageTk, ImageGrab
import os
import json
import random
from tkinterdnd2 import DND_FILES, TkinterDnD

CARD_DB = "cards.json"

class FlashcardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📚 Visual Flashcards - Learn Visually")
        self.root.geometry("850x600")
        self.root.configure(bg="#1c1c1c")
        self.history = []  # <== اضافه شده برای قابلیت برگشت به کارت قبلی

        self.cards = []
        self.current_index = 0
        self.front_image_path = None
        self.back_image_path = None
        self.flipped = False
        self.categories = []
        self.selected_category = tk.StringVar(value="Default")

        self.create_widgets()
        self.load_cards()
        self.update_card_info()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#1c1c1c', foreground='white', font=('Segoe UI', 10))
        style.configure('TButton', background='#444', foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('TLabel', background='#1c1c1c', foreground='white')
        style.configure('TEntry', fieldbackground='#2e2e2e', foreground='white')
        style.configure('TCombobox', fieldbackground='#2e2e2e', background='#2e2e2e', foreground='white')

        title = ttk.Label(self.root, text="🧠 Visual Flashcards", font=('Segoe UI', 16, 'bold'))
        title.pack(pady=10)

        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=5)

        ttk.Label(control_frame, text="Category:").grid(row=0, column=0, padx=5)
        self.category_dropdown = ttk.Combobox(control_frame, textvariable=self.selected_category, values=self.categories, width=25)
        self.category_dropdown.grid(row=0, column=1, padx=5)
        self.category_dropdown.bind("<FocusIn>", lambda e: self.update_categories())

        self.add_cat_button = ttk.Button(control_frame, text="➕ Add", command=self.add_category)
        self.add_cat_button.grid(row=0, column=2, padx=5)

        self.rename_button = ttk.Button(control_frame, text="✏ Rename", command=self.rename_category)
        self.rename_button.grid(row=0, column=3, padx=5)

        self.delete_cat_button = ttk.Button(control_frame, text="🗑 Delete", command=self.delete_category)
        self.delete_cat_button.grid(row=0, column=4, padx=5)

        self.canvas = tk.Canvas(self.root, width=500, height=350, bg='black', highlightthickness=2, highlightbackground='#777')
        self.canvas.pack(pady=15)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=5)

        buttons = [
            ("📥 Front", self.load_front_image),
            ("📥 Back", self.load_back_image),
            ("💾 Save", self.save_card),
            ("🔁 Flip", self.flip_card),
            ("⬅ Back", self.previous_card),  # دکمه برگشت اضافه شد
            ("➡ Next", self.next_card),
            ("❌ Delete", self.delete_card)
        ]

        for i, (text, cmd) in enumerate(buttons):
            btn = ttk.Button(btn_frame, text=text, command=cmd)
            btn.grid(row=0, column=i, padx=6, ipadx=5)

        test_frame = ttk.Frame(self.root)
        test_frame.pack(pady=5)

        self.know_button = ttk.Button(test_frame, text="✅ I knew this", command=lambda: self.mark_card(True))
        self.dontknow_button = ttk.Button(test_frame, text="❓ I didn’t know", command=lambda: self.mark_card(False))
        self.know_button.grid(row=0, column=0, padx=10)
        self.dontknow_button.grid(row=0, column=1, padx=10)

        self.info_label = ttk.Label(self.root, text="Card 0 of 0", font=('Segoe UI', 11, 'bold'))
        self.info_label.pack(pady=5)

        self.feedback_label = ttk.Label(self.root, text="", font=('Segoe UI', 10), foreground="#00ff99")
        self.feedback_label.pack(pady=2)

        self.root.bind("<Control-v>", self.paste_image)
        self.canvas.drop_target_register(DND_FILES)
        self.canvas.dnd_bind('<<Drop>>', self.drop_image)

    def add_category(self):
        name = simpledialog.askstring("New Category", "Enter category name:")
        if name and name not in self.categories:
            self.categories.append(name)
            self.selected_category.set(name)
            self.update_categories()

    def save_card(self):
        if not self.front_image_path or not self.back_image_path:
            messagebox.showerror("Error", "Please add both front and back images")
            return
        category = self.selected_category.get()
        self.cards.append({
            'front': self.front_image_path,
            'back': self.back_image_path,
            'seen': 0,
            'correct': 0,
            'category': category
        })
        self.write_cards()
        self.front_image_path = None
        self.back_image_path = None
        self.canvas.delete("all")
        self.feedback_label.config(text=f"Card saved in category '{category}' ✅")
        self.update_categories()
        self.update_card_info()

    

    def mark_card(self, knew_it):
        if not self.cards:
            return
        card = self.cards[self.current_index]
        card['seen'] = card.get('seen', 0) + 1
        if knew_it:
            card['correct'] = card.get('correct', 0) + 1
            self.feedback_label.config(text="Great! We'll show it less often ✅")
        else:
            self.feedback_label.config(text="No worries! We'll practice it again soon 🔁")
        self.write_cards()
        self.next_card()

    def next_card(self):
        filtered = [i for i, c in enumerate(self.cards) if c.get('category', 'Default') == self.selected_category.get()]
        if not filtered:
            self.feedback_label.config(text="No cards in this category.")
            return
        weights = []
        for i in filtered:
            c = self.cards[i]
            seen = c.get('seen', 0)
            correct = c.get('correct', 0)
            score = 1.0 if seen == 0 else max(0.1, 1.0 - correct / seen)
            weights.append(score)
        total = sum(weights)
        probs = [w / total for w in weights]
        self.history.append(self.current_index)  # <== برای برگشت
        self.current_index = random.choices(filtered, weights=probs, k=1)[0]
        self.show_image(self.cards[self.current_index]['front'])
        self.flipped = False
        self.update_card_info()

    def previous_card(self):
        if self.history:
            self.current_index = self.history.pop()
            self.show_image(self.cards[self.current_index]['front'])
            self.flipped = False
            self.feedback_label.config(text="Showing previous card ⬅")
            self.update_card_info()
        else:
            self.feedback_label.config(text="No previous card.")

    def paste_image(self, event=None):
        try:
            img = ImageGrab.grabclipboard()
            if isinstance(img, Image.Image):
                img_path = f"clipboard_{len(self.cards)}.png"
                img.save(img_path)
                if not self.front_image_path:
                    self.front_image_path = img_path
                    self.show_image(img_path)
                    self.feedback_label.config(text="Front image pasted from clipboard")
                else:
                    self.back_image_path = img_path
                    self.feedback_label.config(text="Back image pasted from clipboard")
        except Exception as e:
            messagebox.showerror("Paste Failed", str(e))




    def rename_category(self):
        old = self.selected_category.get()
        new = tk.simpledialog.askstring("Rename Category", f"Rename '{old}' to:")
        if new and new != old:
            for card in self.cards:
                if card.get('category', 'Default') == old:
                    card['category'] = new
            self.selected_category.set(new)
            self.write_cards()
            self.update_categories()

    def delete_category(self):
        to_delete = self.selected_category.get()
        confirm = messagebox.askyesno("Delete Category", f"Delete all cards in '{to_delete}'?")
        if confirm:
            self.cards = [c for c in self.cards if c.get('category', 'Default') != to_delete]
            self.write_cards()
            self.selected_category.set("Default")
            self.update_categories()
            self.canvas.delete("all")
            self.update_card_info()

    def load_front_image(self):
        path = filedialog.askopenfilename()
        if path:
            self.front_image_path = path
            self.show_image(path)

    def load_back_image(self):
        path = filedialog.askopenfilename()
        if path:
            self.back_image_path = path

    def show_image(self, path):
        img = Image.open(path)
        img = img.resize((400, 300), Image.Resampling.LANCZOS)
        self.tk_img = ImageTk.PhotoImage(img)
        self.canvas.create_image(0, 0, anchor='nw', image=self.tk_img)

    def save_card(self):
        if not self.front_image_path or not self.back_image_path:
            messagebox.showerror("Error", "Please add both front and back images")
            return
        category = self.selected_category.get()
        self.cards.append({
            'front': self.front_image_path,
            'back': self.back_image_path,
            'seen': 0,
            'correct': 0,
            'category': category
        })
        self.write_cards()
        self.front_image_path = None
        self.back_image_path = None
        self.canvas.delete("all")
        messagebox.showinfo("Saved", f"Card saved in category '{category}'")
        self.update_categories()
        self.update_card_info()

    def load_cards(self):
        if os.path.exists(CARD_DB):
            with open(CARD_DB, 'r') as f:
                self.cards = json.load(f)
        self.update_categories()

    def write_cards(self):
        with open(CARD_DB, 'w') as f:
            json.dump(self.cards, f)

    def update_categories(self):
        cats = list(set(c.get('category', 'Default') for c in self.cards))
        self.categories = sorted(cats)
        self.category_dropdown['values'] = self.categories

    def flip_card(self):
        if not self.cards:
            return
        current = self.cards[self.current_index]
        self.show_image(current['back'] if self.flipped else current['front'])
        self.flipped = not self.flipped

    def next_card(self):
        if not self.cards:
            return
        self.current_index = self.select_next_index()
        self.show_image(self.cards[self.current_index]['front'])
        self.flipped = False
        self.update_card_info()

    def delete_card(self):
        if not self.cards:
            return
        del self.cards[self.current_index]
        self.current_index = max(0, self.current_index - 1)
        self.write_cards()
        if self.cards:
            self.show_image(self.cards[self.current_index]['front'])
        else:
            self.canvas.delete("all")
        self.flipped = False
        self.update_categories()
        self.update_card_info()

    def update_card_info(self):
        total = len(self.cards)
        current = self.current_index + 1 if total > 0 else 0
        self.info_label.config(text=f"Card {current} of {total}")


    def drop_image(self, event):
        path = event.data.strip('{}')
        if os.path.exists(path):
            if not self.front_image_path:
                self.front_image_path = path
                self.show_image(path)
            else:
                self.back_image_path = path

    def mark_card(self, knew_it):
        if not self.cards:
            return
        card = self.cards[self.current_index]
        card['seen'] = card.get('seen', 0) + 1
        if knew_it:
            card['correct'] = card.get('correct', 0) + 1
        self.write_cards()
        self.next_card()

    def select_next_index(self):
        import random
        if not self.cards:
            return 0
        filtered_cards = [i for i, c in enumerate(self.cards) if c.get('category', 'Default') == self.selected_category.get()]
        if not filtered_cards:
            return 0
        weights = []
        for i in filtered_cards:
            c = self.cards[i]
            seen = c.get('seen', 0)
            correct = c.get('correct', 0)
            score = 1.0 if seen == 0 else max(0.1, 1.0 - correct / seen)
            weights.append(score)
        total = sum(weights)
        probs = [w / total for w in weights]
        return filtered_cards[random.choices(range(len(filtered_cards)), weights=probs, k=1)[0]]


if __name__ == "__main__":
    try:
        root = TkinterDnD.Tk()
        app = FlashcardApp(root)
        root.mainloop()
    except ImportError:
        messagebox.showerror("Error", "You need to install tkinterdnd2 module.")
        raise
