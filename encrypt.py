#뭔가추가
from Crypto.Cipher import AES
import pickle
import os
from tkinter import *
import tkinter.messagebox
from tkinter import filedialog
from tkinter import dialog
from Crypto.Hash import SHA256 as SHA
filename = ''
import dill
from Structure import filesystem
from Structure import foldersystem
from pathlib import Path
import shutil

#친구야.

def makeWindow():

    def browserButtonOnClick():
        global filename
        filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes=[("all files","*.*")])
       # filename = filedialog.askdirectory()
        filename = filename.replace("\\","/")
        textbox.insert(0, filename)
    def browserButtonOnClick2():
        global filename
       # filename = filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes=[("all files","*.*")])
        filename = filedialog.askdirectory()
        filename = filename.replace("\\","/")
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
            if(new__decrypt(filename,passwordtextbox.get()) == 0):
                deleteFiles(filename)
                tkinter.messagebox.showinfo("Info", "File is unlocked")
            else:
                tkinter.messagebox.showwarning("Warning", "Wrong Password")

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
            result = new__encrypt(filename, None, None, passwordtextbox.get())
            new__serializeToFile(result, filename)

            #encrypt(filename, passwordtextbox.get())
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
    window.title("SquirrelSteak encryption program")
    window.geometry('550x150+600+200')

    frame1 = Frame(window)
    frame1.pack(fill=X, pady = 20)

    labelPath = Label(frame1, text="PATH", width=10)
    labelPath.pack(side=LEFT, padx=5, pady=5)

    path = ""
    textbox = Entry(frame1, width = 35, textvariable = path)
    textbox.pack(side = LEFT, padx=5)

    browserbtn = Button(frame1, text="파일 열기", width=10, command = browserButtonOnClick)
    browserbtn.pack(side=RIGHT, padx=10, pady=10)

    browserbtn2 = Button(frame1, text="폴더 열기", width=10, command = browserButtonOnClick2)
    browserbtn2.pack(side=RIGHT, padx=10, pady=10)

    frame2 = Frame(window)
    frame2.pack(fill=X, )

    encrybtn = Button(frame2, text="암호화", width=20, command = onclick_enc)
    encrybtn.pack(side = LEFT, padx=80, pady=10)

    decrybtn = Button(frame2, text="복호화", width=20, command = onclick_dnc)
    decrybtn.pack(side=LEFT, padx=20, pady=10)

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

def __Encrypt(bytes, password):
    key = changeHashKey(password)
    cipher = AES.new(key,  AES.MODE_EAX)
    ec = cipher.encrypt(bytes)
    return ec,cipher.nonce
def deleteFiles(path):
    try:
        os.remove(path)
    except :
        shutil.rmtree(path)

# 암호화를해서, 저장한다..
def  encrypt(path, password):
    global e_cipher
    key = changeHashKey(password)

    f = open(path, mode='rb')
    byteBuffer = bytearray(f.read())
    fname, ext = os.path.splitext(path)



    fsplit  = fname.split('/')
    fsplitLatest = fsplit.__len__()-1
    fname = fsplit[fsplitLatest]

    savepath = ""
    for x in range(0, fsplit.__len__()-1):
        savepath += fsplit[x]+"/"

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



i = 0

#폴더압축해제할떄
def recur(path, root = foldersystem(), target= foldersystem(), password = str()):
    global i
    i += 1
    ct = None
    currentPath =''
    file = ''
    if(target is None):
        currentPath, file = os.path.split(path)
        print(file)
        ct = root
    else:
        currentPath, file = os.path.split(path)
        file += ".encrypt"
        ct = target


    if(ct.files.__len__() == 0):
        print("=?", path.replace('encrypt',''))
        if (os.path.exists(path.replace('encrypt','')) == False):
            os.mkdir(path.replace('encrypt',''))

    for item in ct.files:
        print(item.filename)
        targetPathDir = currentPath + "/" + file.split('.')[-2] + "/";
        targetPath = currentPath + "/" + file.split('.')[-2] + "/" + item.filename
        print(targetPath)

        print(os.path.exists(targetPathDir))
        if(os.path.exists(targetPathDir) == False):
           print(targetPathDir)
           os.mkdir(targetPathDir)
        f = open(targetPath, "wb")
        cipher = AES.new(changeHashKey(password), AES.MODE_EAX, ct.files[0].nonce)
        bytearray = cipher.decrypt(ct.files[0].filebyte)
        f.write(bytearray)

    for item in ct.folders:
        recur(path.replace('.encrypt','')+"/"+item.foldername, root, item, password)


    return

def new__decrypt(path, password):
    currentPath , file = os.path.split(path)
    print(currentPath)
    v = new__deserializeToFile (path)

    key = changeHashKey(password)

    #얘가  '싱글파일' 일대 해제
    if (v.foldername == '?') :
        a,b = os.path.split(path)
        f = open(a + "/" +v.files[0].filename, "wb")
        if(key == v.files[0].hashpw):
            cipher = AES.new(changeHashKey(password), AES.MODE_EAX, v.files[0].nonce)
            bytearray = cipher.decrypt(v.files[0].filebyte)
            f.write(bytearray)
            return 0
        else:
            return 1

        return
    else :
    #얘는 폴더대상으로  해제
        if(key == v.hashpw):
            recur(path, v, None, password)
            return 0
        else:
            return 1
    return


def new__encrypt(path, root = foldersystem(), target = foldersystem(), password = str()):
    if(root is None):
        root = foldersystem()

    ct = None
    if(target is None):
        ct = root
    else:
        ct = target


    if(os.path.isdir(path) == False):
        fname1, ext1 = os.path.split(path)
        filesys = filesystem()
        filesys.filename = ext1
        f = open(path, "rb")
        bytearray = f.read()
        enc,nonce = __Encrypt(bytearray, password)
        filesys.filebyte =  enc
        filesys.extension = '.exe'
        filesys.nonce = nonce
        filesys.hashpw = changeHashKey(password)
        root.foldername = "?"
        root.files = []
        root.files.append(filesys)
        root.hashpw = changeHashKey(password)
        return root
    else:


        fname = path
        filist = []
        fdlist = []
        ct.files = filist
        ct.folders = fdlist
        ct.foldername = fname.split("/")[-1]
        ct.hashpw = changeHashKey(password)


        datas = os.listdir(path)
        for item in datas:
            if (os.path.isdir(path +"/" + item) == True):
                foldersys = foldersystem()
                foldersys.foldername = item
                fdlist.append(foldersys)
                new__encrypt(path +"/" + item, root, foldersys, password)
            else:
                f = open(path + "/" + item, "rb")
                bytearray = f.read()
                enc, nonce = __Encrypt(bytearray, password)
                fstem = filesystem()
                fstem.filebyte = enc
                fstem.filename = item
                fstem.nonce = nonce
                fstem.hashpw = changeHashKey(password)
                filist.append(fstem)

    return root


def new__serializeToFile(data, path):
    dir = os.path.isdir(path)


    if(dir):

        pt = Path(path)
        ptp = pt.parent
        strr = str(ptp)
        with open(strr + "/" + path.split('/')[-1]+".encrypt", 'wb') as f:
            return pickle.dump(data, f)
        return
    else:
        v =  path.split('.')[0] + ".encrypt"
        with open(v, 'wb') as f:
            return pickle.dump(data, f)

def new__deserializeToFile(path):
    dir = os.path.isdir(path)
    if (dir):
        return
    else:
        v = path.split('.')[0] + ".encrypt"
        with open(v, 'rb') as f:
            return pickle.load(f)
#result = new__encrypt("C:/Users/shlif/Documents/UnityProjectFolder/Utility/Assets/FolderSearch/SearchTest/FolderA/adsadas.txt", None, None,"1234")
#new__serializeToFile(result, "C:/Users/shlif/Documents/UnityProjectFolder/Utility/Assets/FolderSearch/SearchTest/FolderA/adsadas.txt")
#new__decrypt("C:/Users/shlif/Documents/UnityProjectFolder/Utility/Assets/FolderSearch/SearchTest/FolderA/adsadas.encrypt", "1234")


makeWindow()