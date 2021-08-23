#  MIT License
#
# Copyright (c) 2018 glenya
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from Tkinter import *
from Tix import *
from tkFileDialog import askopenfilename
from ctypes import *
from ctypes.wintypes import *

# global vars
proc_name = ""
pid = None
lib_name = ""

root = Tk()
root.title('Inject DLL')

def get_proc_list():
    lst = []
    class PROCESSENTRY32(Structure):
        _fields_ = [
        ('dwSize',              DWORD),     ('cntUsage',            DWORD),     ('th32ProcessId',       DWORD),
        ('th32DefaultHeapId',   DWORD),     ('th32ModuleId',        DWORD),     ('cntThreads',          DWORD),
        ('th32ParentProcessId', DWORD),     ('pcPriClassBase',      LONG),      ('dwFlags',             DWORD),
        ('szExeFile', c_char*MAX_PATH)]
    hSnapshot = None
    try:
        hSnapshot = windll.kernel32.CreateToolhelp32Snapshot(0x02, 0x00)
        pe = PROCESSENTRY32()
        pe.dwSize = sizeof(PROCESSENTRY32)
        curr = windll.kernel32.Process32First(hSnapshot, byref(pe))
        while(curr):
            lst.append((str(pe.szExeFile), (pe.th32ProcessId)))
            curr = windll.kernel32.Process32Next(hSnapshot, byref(pe))
    except Exception, e: print e
    finally: windll.kernel32.CloseHandle(hSnapshot)
    return lst

def select_dll():
    global lib_name
    lib_name = askopenfilename(
    filetypes=(('Dynamic Link Libraries', '*.dll'),))
    if(lib_name == ""): return
    #lib_name = lib_name.replace('/', '\\')
    lib_entry.config(state="normal")
    lib_entry.delete(0, END)
    lib_entry.insert(END, lib_name)
    lib_entry.config(state="readonly")
    lib_ttip.bind_widget(lib_entry, balloonmsg=lib_name)
    if(proc_name == ""): return
    inject_button.config(state="normal")
    
def select_process():
    pl = Toplevel()
    pl.geometry('400x300')
    pl.title("Select process")
    lb = Listbox(pl)
    lb.pack(fill=BOTH, expand=1)
    sb = Scrollbar(lb, orient="vertical", command=lb.yview)
    sb.pack(fill="y", side="right")
    lb.config(yscrollcommand=sb.set)
    proc_list = get_proc_list()
    for proc in proc_list: lb.insert(END, proc[0])
    pl.focus_force()
    def on_double_click(event):
        global proc_name
        global pid
        sel_id = event.widget.curselection()[0]
        proc_name = event.widget.get(sel_id)
        pid = proc_list[int(sel_id)][1]
        if(proc_name == "" or pid == ""): return
        pl.destroy()
        proc_entry.config(state="normal")
        proc_entry.delete(0, END)
        proc_entry.insert(END, proc_name)
        proc_entry.config(state="readonly")
        proc_ttip.bind_widget(proc_entry, balloonmsg=proc_name)
        if(lib_name == ""): return
        inject_button.config(state="normal")
    lb.bind('<Double-1>', on_double_click)

def inject_dll():
    PAGE_READWRITE = 0x04
    PROCESS_ALL_ACCESS = 0x1F0FFF
    path_len = len(str(lib_name))
    h_process = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
    if not h_process: root.destroy()
    alloc = windll.kernel32.VirtualAllocEx(h_process, 0, path_len, 0x1000|0x2000, PAGE_READWRITE)
    windll.kernel32.WriteProcessMemory(h_process, alloc, str(lib_name), path_len, 0)
    h_kernel32 = windll.kernel32.GetModuleHandleA("kernel32.dll")
    h_loadlibrary = windll.kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
    if not windll.kernel32.CreateRemoteThread(h_process, None, 0, h_loadlibrary, alloc, 0, 0):
        root.destroy()
    
Label(text='Process:').grid(row=0, column=0, sticky=E)
Label(text='DLL path:').grid(row=1, column=0, sticky=E)
proc_entry = Entry()
proc_entry.config(state="disabled")
proc_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
lib_entry = Entry()
lib_entry.config(state="disabled")
lib_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
proc_ttip = Balloon(root)
lib_ttip = Balloon(root)
Button(text='Select...', width=10, height=1, command=select_process).grid(row=0, column=3, padx=5, pady=5)
Button(text='Browse...', width=10, height=1, command=select_dll).grid(row=1, column=3, padx=5, pady=5)
inject_button = Button(text='Inject', width=10, height=1, state=DISABLED, command=inject_dll)
inject_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
Button(text='Close', width=10, height=1, command=root.destroy).grid(row=3, column=2, columnspan=2, padx=5, pady=5)

root.focus_force()
root.mainloop()