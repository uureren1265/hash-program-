import os
import hashlib
import tkinter as tk
from tkinter import messagebox

ALGORITMALAR = ["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b", "ripemd160", "whirlpool"]

def veriyi_sifrele(veri, algoritma):
    if algoritma == "md5":
        return hashlib.md5(veri.encode()).hexdigest()
    elif algoritma == "sha1":
        return hashlib.sha1(veri.encode()).hexdigest()
    elif algoritma == "sha256":
        return hashlib.sha256(veri.encode()).hexdigest()
    elif algoritma == "sha512":
        return hashlib.sha512(veri.encode()).hexdigest()
    elif algoritma == "sha3_256":
        return hashlib.sha3_256(veri.encode()).hexdigest()
    elif algoritma == "blake2b":
        return hashlib.blake2b(veri.encode()).hexdigest()
    elif algoritma == "ripemd160":
        return hashlib.new('ripemd160', veri.encode()).hexdigest()
    elif algoritma == "whirlpool":
        return hashlib.new('whirlpool', veri.encode()).hexdigest()
    else:
        raise ValueError(f"Desteklenmeyen algoritma: {algoritma}")

def hash_cozme(hash_degeri, hash_dosyalar):
    for dosya in hash_dosyalar:
        if os.path.exists(dosya):
            with open(dosya, "r") as dosya_icerik:
                for satir in dosya_icerik:
                    parcalar = satir.strip().split(":")
                    if len(parcalar) == 2 and parcalar[1] == hash_degeri:
                        return parcalar[0]
    return "Eşleşen hash değeri bulunamadı."

def panoya_kopyala():
    icerik = sonuc_metni.get(1.0, tk.END).strip()
    if icerik:
        pencere.clipboard_clear()
        pencere.clipboard_append(icerik)
        pencere.update()
        basari_mesaji_goster("Başarıyla kopyalandı!")
    else:
        messagebox.showwarning("Boş", "Kopyalanacak bir şey yok!")

def basari_mesaji_goster(mesaj):
    global basari_etiketi
    basari_etiketi.config(text=mesaj)
    basari_etiketi.pack(pady=10)
    pencere.after(2000, mesaj_gizle)

def mesaj_gizle():
    basari_etiketi.config(text="")
    basari_etiketi.pack_forget()

def yapistirma_islemi(event, kutu_widget):
    kutu_widget.delete(0, tk.END)
    panodaki_icerik = pencere.clipboard_get()
    kutu_widget.insert(0, panodaki_icerik)
    return "break"

def gui_islet():
    def sifrele_butonuna_bas():
        veri = veri_girdisi.get()
        algoritma = algoritma_secimi.get().lower()
        if not veri:
            messagebox.showerror("Veri Hatası", "Lütfen şifrelemek için veri girin.")
            return
        try:
            sifrelenmis_veri = veriyi_sifrele(veri, algoritma)
            sonuc_metni.delete(1.0, tk.END)
            sonuc_metni.insert(tk.END, sifrelenmis_veri)
        except ValueError as e:
            messagebox.showerror("Hata", f"Hata: {e}")

    def cozme_butonuna_bas():
        hash_degeri = hash_girdisi.get()
        if not hash_degeri:
            messagebox.showerror("Veri Hatası", "Lütfen çözmek için hash değeri girin.")
            return
        hash_dosyalar = ["hashed_output.txt"]
        sonuc = hash_cozme(hash_degeri, hash_dosyalar)
        sonuc_metni.delete(1.0, tk.END)
        sonuc_metni.insert(tk.END, sonuc)

    def temizle():
        sonuc_metni.delete(1.0, tk.END)

    global pencere
    pencere = tk.Tk()
    pencere.title("Hash Şifreleme ve Çözme")
    pencere.geometry("1000x800")
    pencere.config(bg="#f0f0f0")

    baslik_etiketi = tk.Label(pencere, text="Hash Şifreleme ve Çözme", font=("Arial", 16, "bold"), bg="#f0f0f0")
    baslik_etiketi.pack(pady=10)

    veri_etiketi = tk.Label(pencere, text="Şifrelemek için veri girin:", bg="#f0f0f0", font=("Arial", 10))
    veri_etiketi.pack(pady=5)

    veri_girdisi = tk.Entry(pencere, width=50, font=("Arial", 12))
    veri_girdisi.pack(pady=5)

    algoritma_etiketi = tk.Label(pencere, text="Algoritma seçin:", bg="#f0f0f0", font=("Arial", 10))
    algoritma_etiketi.pack(pady=5)

    algoritma_secimi = tk.StringVar()
    algoritma_secimi.set(ALGORITMALAR[0])
    algoritma_dropdown = tk.OptionMenu(pencere, algoritma_secimi, *ALGORITMALAR)
    algoritma_dropdown.config(font=("Arial", 10))
    algoritma_dropdown.pack(pady=5)

    sifrele_butonu = tk.Button(pencere, text="Şifrele", command=sifrele_butonuna_bas, bg="#4CAF50", fg="white", font=("Arial", 12))
    sifrele_butonu.pack(pady=10)

    hash_etiketi = tk.Label(pencere, text="Çözmek için hash değeri girin:", bg="#f0f0f0", font=("Arial", 10))
    hash_etiketi.pack(pady=5)

    hash_girdisi = tk.Entry(pencere, width=50, font=("Arial", 12))
    hash_girdisi.pack(pady=5)

    hash_girdisi.bind("<Control-v>", lambda event: yapistirma_islemi(event, hash_girdisi))

    cozme_butonu = tk.Button(pencere, text="Çöz", command=cozme_butonuna_bas, bg="#2196F3", fg="white", font=("Arial", 12))
    cozme_butonu.pack(pady=10)

    global sonuc_metni
    sonuc_metni = tk.Text(pencere, height=10, width=50, font=("Arial", 12))
    sonuc_metni.pack(pady=10)

    temizle_butonu = tk.Button(pencere, text="Sonuçları Temizle", command=temizle, bg="#FFC107", fg="black", font=("Arial", 12))
    temizle_butonu.pack(pady=5)

    kopyala_butonu = tk.Button(pencere, text="Kopyala", command=panoya_kopyala, bg="#FF5722", fg="white", font=("Arial", 12))
    kopyala_butonu.pack(pady=5)

    cikis_butonu = tk.Button(pencere, text="Çıkış", command=pencere.quit, bg="#9E9E9E", fg="white", font=("Arial", 12))
    cikis_butonu.pack(pady=5)

    global basari_etiketi
    basari_etiketi = tk.Label(pencere, text="", font=("Arial", 12, "italic"), fg="green", bg="#f0f0f0")
    
    pencere.mainloop()

if __name__ == "__main__":
    gui_islet()
