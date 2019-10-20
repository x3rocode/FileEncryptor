#뭔가추가
from Crypto.Cipher import AES
import pickle
import os
from tkinter import *
import tkinter.messagebox
from tkinter import filedialog
from Crypto.Hash import SHA256 as SHA
filename = ''


class  filesystem():
    filebyte   = bytearray() #암호화됨
    hashpw = bytearray()
    filename   = str()
    extension  = str()
    nonce = str()



def makeWindow():

    def browserButtonOnClick():
        global filename
        filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes=[("all files","*.*")])
        filename = filename.replace("/","\\")
        textbox.insert(0, filename)

    def relasePassword():
        relpwWindow = Tk()
        relpwWindow.title("release Password")
        relpwWindow.geometry('300x100+700+300')

        relpwframe1 = Frame(relpwWindow)
        relpwframe1.pack(fill=X, pady=10)

        passwordlabel = Label(relpwframe1, text="Password", width=10)
        passwordlabel.pack(side=LEFT, padx=5, pady=10)

        passwordtextbox = Entry(relpwframe1, width=40)
        passwordtextbox.pack(side=LEFT, padx=5, expand=True)

        relpwframe2 = Frame(relpwWindow)
        relpwframe2.pack(fill=X)

        # action_with_arg = partial(encrypt, filename, password)
        def a():
            if (decrypt(filename, passwordtextbox.get()) == 0):
                deleteFiles(filename)
                tkinter.messagebox.showinfo("Info", "File is unlocked")
            elif (decrypt(filename, passwordtextbox.get()) == 1):
                tkinter.messagebox.showwarning("Warning", "Wrong password")
            relpwWindow.destroy()

        unlockbtn = Button(relpwframe2, text="UNLOCK", width=10, command=a)
        unlockbtn.pack(padx=10, pady=10)

        relpwWindow.mainloop()

    def setPassword():
        passwordWindow = Tk()
        passwordWindow.title("Setting Password")
        passwordWindow.geometry('300x100+700+300')

        passframe1 = Frame(passwordWindow)
        passframe1.pack(fill=X, pady = 10)

        passwordlabel = Label(passframe1, text="Password", width=10)
        passwordlabel.pack(side=LEFT, padx=5, pady=10)


        passwordtextbox = Entry(passframe1, width=40)
        passwordtextbox.pack(side=LEFT, padx=5, expand=True)

        passframe2 = Frame(passwordWindow)
        passframe2.pack(fill=X )

        #action_with_arg = partial(encrypt, filename, password)

        def  a():
            encrypt(filename, passwordtextbox.get())
            deleteFiles(filename)
            tkinter.messagebox.showinfo("Info", "File is locked")
            passwordWindow.destroy()

        lockbtn = Button(passframe2, text="LOCK", width=10, command = a)
        lockbtn.pack( padx=10, pady=10)

        passwordWindow.mainloop()


    def pathEmpty():
        tkinter.messagebox.showwarning("Warning", "File Path Empty")

    def onclick_enc():
        global filename
        if(filename == ""):
            pathEmpty()
        else:
            setPassword()


    def onclick_dnc():
        global filename
        if (filename == ""):
            pathEmpty()
        else:
            relasePassword()


    window = Tk()
    window.title("file encryption program")
    window.geometry('500x150+600+200')

    frame1 = Frame(window)
    frame1.pack(fill=X, pady = 20)

    labelPath = Label(frame1, text="PATH", width=10)
    labelPath.pack(side=LEFT, padx=10, pady=10)

    path = ""
    textbox = Entry(frame1, width = 40, textvariable = path)
    textbox.pack(side = LEFT, padx=10, expand=True)

    browserbtn = Button(frame1, text="browser", width=10, command = browserButtonOnClick)
    browserbtn.pack(side=RIGHT, padx=10, pady=10)

    frame2 = Frame(window)
    frame2.pack(fill=X, )

    encrybtn = Button(frame2, text="encryption", width=20, command = onclick_enc)
    encrybtn.pack(side = LEFT, padx=50, pady=10)

    decrybtn = Button(frame2, text="decryption", width=20, command = onclick_dnc)
    decrybtn.pack(side=LEFT, padx=50, pady=10)
    window.mainloop()

def serializeClassAndSave(data, savepath):
    v = savepath + data.filename + '.encrypt'
    with open(v, 'wb') as f:
        return pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)


def deserlaizeClassByFile(path):
    ff = open(path, "rb")
    v = pickle.load(ff)
    return v

def saveFile(path, data):
    v = open(path, 'wb')
    v.write(data)

def changeHashKey(password):
    hash = SHA.new()
    hash.update(password.encode('utf-8'))

    key = hash.digest()

    return key

def deleteFiles(path):
    os.remove(path)

# 암호화를해서, 저장한다..
def  encrypt(path, password):
    global e_cipher
    key = changeHashKey(password)

    f = open(path, mode='rb')
    byteBuffer = bytearray(f.read())
    fname, ext = os.path.splitext(path)



    fsplit  = fname.split('\\')
    fsplitLatest = fsplit.__len__()-1
    fname = fsplit[fsplitLatest]

    savepath = ""
    for x in range(0, fsplit.__len__()-1):
        savepath += fsplit[x]+"\\"

    value = byteBuffer

    e_cipher = AES.new(key, AES.MODE_EAX)
    ciphertext = e_cipher.encrypt(value)

    file1 = filesystem()
    file1.filebyte = ciphertext
    file1.hashpw = key
    file1.filename = fname
    file1.extension = ext[1:]
    file1.nonce = e_cipher.nonce
    serializeClassAndSave(file1, savepath)
    return
def decrypt(path, password):
    global e_cipher

    key = changeHashKey(password)
    loadedFile = deserlaizeClassByFile(path)

    realkey  = loadedFile.hashpw

    if(key != realkey):
        return 1
    else:
        e_cipher = AES.new(key, AES.MODE_EAX, loadedFile.nonce)
        data = e_cipher.decrypt(loadedFile.filebyte)
        saveFile(filename.replace('encrypt', loadedFile.extension), data)
        return 0
makeWindow()