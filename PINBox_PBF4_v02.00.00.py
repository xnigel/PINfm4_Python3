
# _____/\\\\\\\\\\\\\________________________/\\\____________________________________
#  ____\/\\\/////////\\\_____________________\/\\\____________________________________
#   ____\/\\\_______\/\\\__/\\\_______________\/\\\____________________________________
#    ____\/\\\\\\\\\\\\\/__\///___/\\/\\\\\\___\/\\\____________/\\\\\_____/\\\____/\\\_
#     ____\/\\\/////////_____/\\\_\/\\\////\\\__\/\\\\\\\\\____/\\\///\\\__\///\\\/\\\/__
#      ____\/\\\_____________\/\\\_\/\\\__\//\\\_\/\\\////\\\__/\\\__\//\\\___\///\\\/____
#       ____\/\\\_____________\/\\\_\/\\\___\/\\\_\/\\\__\/\\\_\//\\\__/\\\_____/\\\/\\\___
#        ____\/\\\_____________\/\\\_\/\\\___\/\\\_\/\\\\\\\\\___\///\\\\\/____/\\\/\///\\\_
#         ____\///______________\///__\///____\///__\/////////______\/////_____\///____\///__
#          _____/\\\\\_____/\\\____________________________________/\\\\\\____________________
#           ____\/\\\\\\___\/\\\___________________________________\////\\\____________________
#            ____\/\\\/\\\__\/\\\__/\\\___/\\\\\\\\____________________\/\\\____________________
#             ____\/\\\//\\\_\/\\\_\///___/\\\////\\\_____/\\\\\\\\_____\/\\\____________________
#              ____\/\\\\//\\\\/\\\__/\\\_\//\\\\\\\\\___/\\\/////\\\____\/\\\____________________
#               ____\/\\\_\//\\\/\\\_\/\\\__\///////\\\__/\\\\\\\\\\\_____\/\\\____________________
#                ____\/\\\__\//\\\\\\_\/\\\__/\\_____\\\_\//\\///////______\/\\\____________________
#                 ____\/\\\___\//\\\\\_\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__/\\\\\\\\\_________________
#                  ____\///_____\/////__\///___\////////_____\//////////__\/////////__________________
# _____________________________________________________________________________________________________

#   Initial version was built in March 2017                                      #
#                                                                                #
#   Version Number Defination:                                                   #
#   v00.02.02 20170321                                                           #
#    -- -- --                                                                    #
#     |  |  |                                                                    #
#     |  |  +------     GUI Updates                                              #
#     |  +---------     Crypto Function Updates                                  #
#     +------------     Published Version (Major Change)                         #
#                                                                                #
# _______________________________________________________________________________#
#
#   Change log:
#
#   01. 00.01.01    PIN block format 0 encryption is completed!
#   02. 00.02.02    GUI changed (highlight for entry) still working on Decryption
#   03. 01.00.00    All functions and GUI are set!! Good to go!!!
#   04. 01.01.01    Added a mode selector allowing AES operation in different mode
#   05. 02.00.00    Upgrade PinBox from Python2 to Python3 and released on 2023.09.20
# _______________________________________________________________________________#


from tkinter import *
from tkinter import messagebox, filedialog, messagebox, ttk

#   Crypto import
from Crypto.Cipher import DES, DES3, AES
from Crypto.Hash import SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from Crypto import Random
from datetime import date
import os
import socket
import string
import select
import binascii
import time

def update_timeText():
    # Get the current time, note you can change the format as you wish
    current = time.strftime("%Y/%m/%d  %H:%M:%S")
    # Update the timeText Label box with the current time
    realtime.configure(text=current)
    # Call the update_timeText() function after 1 second
    root.after(100, update_timeText)


root = Tk()
PinB_ver = "02.00.00"
PinB_yr = "2023.09.20"
root.title('PINBox' + " (v" + PinB_ver +")")
root.geometry("480x610+900+300")    #("490x600+20+20") for Linux; ("530+470+20+20") for Windows
root.minsize(480, 610)
root.maxsize(480, 610)
pin_format_tab = ttk.Notebook(root)
format_f4 = ttk.Frame(pin_format_tab)

pin_format_tab.add(format_f4, text='PinBlock\nformat 4')
pin_format_tab.pack()
algo_SLC_TDES = IntVar()
F4_TDES_operation = IntVar()
F1_TDES_operation = IntVar()
rnd_gen_operation = IntVar()
f4_AES_operation = IntVar()
aes_mode_select = IntVar()
operation_SLC_AES = IntVar()
operation_SLC_RSA = IntVar()

default_AES_key  = StringVar(format_f4, value = "0123456789ABCDEF123456789ABCDEF0")
default_iv_16B   = StringVar(format_f4, value = "00000000000000000000000000000000")

# Create a timeText Label (a text box)
realtime = Label(root, text="", font=("Helvetica", 20))
realtime.pack(side=LEFT)
# Creat a Exit button
exit_button = Button(root, text="Exit", width=10, bg='#FF5C5C', command=quit)
exit_button.pack(side=RIGHT)
exit_button.place(x=389, y=580)

class MenuBar(Frame):
    def __init__(self):
        Frame.__int__(self)
        self.menubar = Menu(self)
        menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(lable="About", menu=menu)
        menu.add_command(label="Copyright")


class PinBox(Tk):
    #   GUI interface definition
    print("\n\n===================================")
    print("|--  Welcome to use PinBox      --|")
    print("|--                             --|")
    print("|-- Author  : nigel.zhai@ul.com --|")
    print("|-- Version :", PinB_ver, "         --|")
    print("|-- Date    :", PinB_yr, "       --|")
    print("===================================\n\n")
    #   Crypto function - DES

    def clear_F4(self):
        clearing_flag = f4_AES_operation.get()

        #   When Encrypt mode is selected
        if clearing_flag == 1:
            #self.format_f4_key_txt.delete(1.0, END)
            #self.format_f4_iv_txt.delete(1.0, END)
            # self.format_f4_PIN_txt.delete(0, END)
            #self.format_f4_PAN_txt.delete(1.0, END)
            # self.format_f4_rnd_field_txt.delete(0, END)
            self.format_f4_PIN_field_txt.delete(1.0, END)
            self.format_f4_PAN_field_txt.delete(1.0, END)
            self.format_f4_interA_txt.delete(1.0, END)
            self.format_f4_interB_txt.delete(1.0, END)
            #self.format_f4_pinBK_plain_txt.delete(1.0, END)
            self.format_f4_pinBK_cipher_txt.delete(1.0, END)
        #   When Decrypt mode is selected
        elif clearing_flag == 2:
            #self.format_f4_key_txt.delete(1.0, END)
            #self.format_f4_iv_txt.delete(1.0, END)
            self.format_f4_PIN_txt.delete(0, END)
            #self.format_f4_PAN_txt.delete(1.0, END)
            self.format_f4_rnd_field_txt.delete(0, END)
            self.format_f4_PIN_field_txt.delete(1.0, END)
            self.format_f4_PAN_field_txt.delete(1.0, END)
            self.format_f4_interA_txt.delete(1.0, END)
            self.format_f4_interB_txt.delete(1.0, END)
            #self.format_f4_pinBK_plain_txt.delete(1.0, END)
            # self.format_f4_pinBK_cipher_txt.delete(1.0, END)
        else:
            pass


    def submit_F4(self):
        enc_dec_flag = f4_AES_operation.get()
        rnd_flag = rnd_gen_operation.get()

        #   PIN block encryption mode && rng_specified        
        if enc_dec_flag == 1 and rnd_flag == 1:
            print("\nPIN Block format 4 encryption starts:")
            print("Fill 'rnd field' manually:\n")
            self.format_f4_key_txt.configure(bg="#FFFFBF")
            self.format_f4_iv_txt.configure(bg="#FFFFBF")
            self.format_f4_PIN_txt.configure(bg="#FFFFBF")
            self.format_f4_PAN_txt.configure(bg="#FFFFBF")
            self.format_f4_pinBK_cipher_txt.configure(bg="white")
            self.format_f4_rnd_field_lb.configure(fg='black')
            self.format_f4_rnd_field_txt.configure(bg='#FFFFBF', state="normal")
            #self.format_f4_pinBK_plain_lb.configure(fg="gray")
            #self.format_f4_pinBK_plain_txt.configure(bg="light gray", state=DISABLED)

        #   PIN block encryption mode && rng_random_gen 
        elif enc_dec_flag == 1 and rnd_flag == 2:
            print("\nPIN Block format 4 encryption starts:")
            print("Fill 'rnd field' automatically:\n")
            self.format_f4_key_txt.configure(bg="#FFFFBF")
            self.format_f4_iv_txt.configure(bg="#FFFFBF")
            self.format_f4_PIN_txt.configure(bg="#FFFFBF")
            self.format_f4_PAN_txt.configure(bg="#FFFFBF")
            self.format_f4_pinBK_cipher_txt.configure(bg="white")
            self.format_f4_rnd_field_lb.configure(fg="gray")
            self.format_f4_rnd_field_txt.delete(0, END)
            self.format_f4_rnd_field_txt.configure(bg="light gray", state = DISABLED)
            #self.format_f4_pinBK_plain_lb.configure(fg="gray")
            #self.format_f4_pinBK_plain_txt.configure(bg="light gray", state=DISABLED)            

        #   PIN block decryption mode
        elif enc_dec_flag == 2 : 
            print("\nPIN Block format 4 decryption starts:\n")
            self.format_f4_key_txt.configure(bg="#FFFFBF")
            self.format_f4_iv_txt.configure(bg="#FFFFBF")
            self.format_f4_PIN_txt.configure(bg="white")
            self.format_f4_PAN_txt.configure(bg="#FFFFBF")
            self.format_f4_pinBK_cipher_txt.configure(bg="#FFFFBF")
            self.format_f4_rnd_field_lb.configure(fg="black")
            self.format_f4_rnd_field_txt.configure(bg="white", state="normal")
            #self.format_f4_pinBK_plain_lb.configure(fg="black")
            #self.format_f4_pinBK_plain_txt.configure(bg="white", state="normal")


    def execution_F4(self):
        
        rnd_flag = rnd_gen_operation.get()
        f4_operation = f4_AES_operation.get()

        #   rnd gen!!!
        if rnd_flag == 1:
            #print("\nrnd_flag:", rnd_flag)
            rnd_fill = self.format_f4_rnd_field_txt.get()
        elif rnd_flag == 2:
            #print("\nrnd_flag:", rnd_flag)
            rnd_file = Random.new()
            rnd = rnd_file.read(8)
            rnd_fill = rnd.hex()

        key_aes_raw = self.format_f4_key_txt.get()
        key_aes = bytes.fromhex(key_aes_raw.replace(' ', ''))
        iv_raw = self.format_f4_iv_txt.get()
        iv_aes = bytes.fromhex(iv_raw.replace(' ', ''))

        #   getting PAN field:
        PAN_value_raw = self.format_f4_PAN_txt.get()
        PAN_len = len(PAN_value_raw)

        if (PAN_len < 12):
            self.format_f4_pinBK_cipher_txt.delete(1.0, END)
            self.format_f4_pinBK_cipher_txt.insert(1.0, "Make sure the length of PIN or PAN is correct!")
            #break
        elif (PAN_len >= 12 and PAN_len < 20):
            M = PAN_len-12

        PAN_field = str(M) + str(PAN_value_raw) + (31-PAN_len)*"0"

        self.format_f4_PAN_field_txt.delete(1.0, END)
        self.format_f4_PAN_field_txt.insert(1.0, PAN_field)

        if f4_operation == 0:
            self.format_f4_pinBK_cipher_txt.delete(1.0, END)
            self.format_f4_pinBK_cipher_txt.insert(1.0, "Please select a operation!")
        elif f4_operation == 1: #Encryption
            PIN_value_raw = self.format_f4_PIN_txt.get()
            PIN_len = len(PIN_value_raw)
            PIN_field = "4" + str(PIN_len) + str(PIN_value_raw) + (14-PIN_len)*"A" + rnd_fill

            self.format_f4_PIN_field_txt.delete(1.0, END)
            self.format_f4_PIN_field_txt.insert(1.0, PIN_field)

            PIN_field_in = bytes.fromhex(PIN_field.replace(' ', ''))
            PAN_field_in = bytes.fromhex(PAN_field.replace(' ', ''))


            #   Intermediate Block A calculating:
            mode_selector = aes_mode_select.get()
            if mode_selector == 1:
                mode = DES.MODE_CBC
                obj = AES.new(key_aes, mode, iv_aes)
            elif mode_selector == 2:
                mode = DES.MODE_ECB
                obj = AES.new(key_aes, mode)
            
            inter_BK_A_raw = obj.encrypt(PIN_field_in)
            inter_BK_A = inter_BK_A_raw.hex().upper()

            #print("\nintern_BK_A:", inter_BK_A)
            self.format_f4_interA_txt.delete(1.0, END)
            self.format_f4_interA_txt.insert(1.0, inter_BK_A)

            #   xor operation to calculate Intermediate Block B:
            if len(PIN_field) != len(PAN_field):
                self.format_f4_pinBK_cipher_txt.delete(1.0, END)
                self.format_f4_pinBK_cipher_txt.insert(1.0, "Make sure the length of PIN or PAN is correct!")
            else:
                pass

            xor_interA = bytes.fromhex(inter_BK_A.replace(' ', ''))
            xor_PAN_in = bytes.fromhex(PAN_field.replace(' ', ''))

            val_inB = ''
            val_inB = bytes(a ^ b for (a, b) in zip(xor_interA, xor_PAN_in))
            self.format_f4_interB_txt.delete(1.0, END)
            self.format_f4_interB_txt.insert(1.0, val_inB.hex().upper())


            #   Enciphered PIN Block: (last step of encryption)
            mode_selector = aes_mode_select.get()
            if mode_selector == 1:
                mode = DES.MODE_CBC
                obj = AES.new(key_aes, mode, iv_aes)
            elif mode_selector == 2:
                mode = DES.MODE_ECB
                obj = AES.new(key_aes, mode)
            enciphered_PIN_raw = obj.encrypt(val_inB)
            enciphered_PIN = enciphered_PIN_raw.hex().upper()
            self.format_f4_pinBK_cipher_txt.delete(1.0, END)
            self.format_f4_pinBK_cipher_txt.insert(1.0, enciphered_PIN)

        elif f4_operation == 2: #Decryption
            #mode = AES.MODE_ECB
            PINBK_input_raw = self.format_f4_pinBK_cipher_txt.get("1.0", END)
            # PINBK_input = PINBK_input_raw[0:-1].decode('hex')
            PINBK_input = bytes.fromhex(PINBK_input_raw[0:-1].replace(' ', ''))
            
            #   Decryption!!
            mode_selector = aes_mode_select.get()
            if mode_selector == 1:
                mode = DES.MODE_CBC
                obj = AES.new(key_aes, mode, iv_aes)
            elif mode_selector == 2:
                mode = DES.MODE_ECB
                obj = AES.new(key_aes, mode)

            # obj = AES.new(key_aes, mode, iv_aes)
            dec_inB_raw = obj.decrypt(PINBK_input)
            dec_inB = dec_inB_raw.hex().upper()
            #print("\ndec_inB:", dec_inB)
            self.format_f4_interB_txt.delete(1.0, END)
            self.format_f4_interB_txt.insert(1.0, dec_inB)

            xor_dec_interB = bytes.fromhex(dec_inB.replace(' ', ''))
            xor_dec_PAN = bytes.fromhex(PAN_field.replace(' ', ''))

            dec_inA = ''
            dec_inA = bytes(a ^ b for (a, b) in zip(xor_dec_interB, xor_dec_PAN))
            self.format_f4_interA_txt.delete(1.0, END)
            self.format_f4_interA_txt.insert(1.0, dec_inA.hex().upper())

            mode_selector = aes_mode_select.get()
            if mode_selector == 1:
                mode = DES.MODE_CBC
                obj = AES.new(key_aes, mode, iv_aes)
            elif mode_selector == 2:
                mode = DES.MODE_ECB
                obj = AES.new(key_aes, mode)

            dec_plain_PIN_field_raw = obj.decrypt(dec_inA)
            
            dec_plain_PIN_field = dec_plain_PIN_field_raw.hex().upper()
            self.format_f4_PIN_field_txt.delete(1.0, END)
            self.format_f4_PIN_field_txt.insert(1.0, dec_plain_PIN_field)

            PIN_len = dec_plain_PIN_field[1:2]
            PIN_val = dec_plain_PIN_field[2:int(PIN_len)+2]
            rnd_val = dec_plain_PIN_field[16:].upper()

            self.format_f4_PIN_txt.delete(0, END)
            self.format_f4_PIN_txt.insert(0, PIN_val)
            self.format_f4_rnd_field_txt.delete(0, END)
            self.format_f4_rnd_field_txt.insert(0, rnd_val)


    def contact_developer(self):
        tkMessageBox.showinfo("Developer info", "nigel.zhai@ul.com\n\nThank you for your feedback!")
        #webbrowser.open_new(r"fill-a-web-address-start-with-http://")


    #=========================================================================================================
    #   Create Frame/Label/Text/...etc
    def __init__(self, *args, **kwargs):

        #   ============================================================================================================
        #   0.1 Pinblock 0 Enc/Dec
        #   ------------------------------------------------------------------------------------------------------------

        #   ============================================================================================================
        #   1.1 Pinblock 1 Enc/Dec
        #   ------------------------------------------------------------------------------------------------------------

        #   ============================================================================================================
        #   2.1 Pinblock 2 Enc/Dec
        #   ------------------------------------------------------------------------------------------------------------

        #   ============================================================================================================
        #   3.1 Pinblock 3 Enc/Dec
        #   ------------------------------------------------------------------------------------------------------------

        #   ============================================================================================================
        #   4.1 Pinblock 4 Enc/Dec
        #   ------------------------------------------------------------------------------------------------------------
        
        ### ===========================================================================================
        ### Enc/Dec - title
        self.format_f4_Enc_or_Dec = LabelFrame(format_f4, text="Enc/Dec", font=("Helvetica", 12, "bold"), padx=3, pady=3, bd=4)
        self.format_f4_Enc_or_Dec.grid(row=0, column=1, rowspan=3, sticky=W+E)

            #   Enc/Dec - Enc
        self.format_f4_Enc_label_butt = Radiobutton(self.format_f4_Enc_or_Dec, text="Encrypt ", indicatoron=1, value=1, width=5, variable=f4_AES_operation)
        self.format_f4_Enc_label_butt.grid(row=1, column=1, padx=1, pady=1, sticky=W)

            #   Enc/Dec - Dec
        self.format_f4_Dec_label_butt = Radiobutton(self.format_f4_Enc_or_Dec, text="Decrypt ", indicatoron=1, value=2, width=5, variable=f4_AES_operation)
        self.format_f4_Dec_label_butt.grid(row=2, column=1, padx=1, pady=1, sticky=W)
        ### -------------------------------------------------------------------------------------------
        ### RND in PIN field - title
        self.format_f4_rnd_field = LabelFrame(format_f4, text="rnd field", font=("Helvetica", 12, "bold"), padx=3, pady=3, bd=4)
        self.format_f4_rnd_field.grid(row=0, column=2, rowspan=3, sticky=W+E)

            #   RND in PIN field - specified
        self.format_f4_self_rnd = Radiobutton(self.format_f4_rnd_field, text="specified", indicatoron=1, value=1, width=5, variable=rnd_gen_operation)
        self.format_f4_self_rnd.grid(row=1, column=2, padx=1, pady=1, sticky=W)

            #   RND in PIN field - auto gen
        self.format_f4_self_rnd = Radiobutton(self.format_f4_rnd_field, text="auto gen", indicatoron=1, value=2, width=5, variable=rnd_gen_operation)
        self.format_f4_self_rnd.grid(row=2, column=2, padx=1, pady=1, sticky=W)
        ### -------------------------------------------------------------------------------------------
        ### Modes - title
        self.format_f4_mode_select = LabelFrame(format_f4, text="Modes", font=("Helvetica", 12, "bold"), padx=3,pady=3, bd=4)
        self.format_f4_mode_select.grid(row=0, column=3, rowspan=3, sticky=W+E)

            # Modes - CBC
        self.format_f4_self_rnd = Radiobutton(self.format_f4_mode_select, text="CBC   ", indicatoron=1, value=1, width=5, variable=aes_mode_select)
        self.format_f4_self_rnd.grid(row=1, column=3, padx=1, pady=1, sticky=W)

            # Modes - ECB
        self.format_f4_self_rnd = Radiobutton(self.format_f4_mode_select, text="ECB   ", indicatoron=1, value=2, width=5, variable=aes_mode_select)
        self.format_f4_self_rnd.grid(row=2, column=3, padx=1, pady=1, sticky=W)
        ### -------------------------------------------------------------------------------------------
        ### Button - Clear
        self.format_f4_EncDec_submit = Button(format_f4, text="Submit", width=10, command=self.submit_F4)
        self.format_f4_EncDec_submit.grid(row=3, column=3, padx=3, pady=3, sticky=E)

        ### Button - Submit
        self.format_f4_content_clear = Button(format_f4, text="Clear", width=10, command=self.clear_F4)
        self.format_f4_content_clear.grid(row=3, column=2, padx=3, pady=3, sticky=E)


        ### ===========================================================================================
        #   0.2 Key Entry Textbox
        self.format_f4_key_lb = Label(format_f4, text="Key value\n(AES key)")
        self.format_f4_key_lb.grid(row=4, column=0, sticky=E)
        self.format_f4_key_txt = Entry(format_f4, textvariable = default_AES_key, font = "Courier 9", width=56)
        self.format_f4_key_txt.grid(row=4, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   RULER !
        self.format_f4_ruler_1 = Label(format_f4, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9",width=48)
        self.format_f4_ruler_1.grid(row=5, column=1, columnspan=3, padx=6, pady=1, sticky=W)

        #   0.3 IV Entry Textbox
        self.format_f4_iv_lb = Label(format_f4, text="IV")
        self.format_f4_iv_lb.grid(row=6, column=0, sticky=E)
        self.format_f4_iv_txt = Entry(format_f4, textvariable = default_iv_16B, font = "Courier 9", width=56)
        self.format_f4_iv_txt.grid(row=6, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   0.4 PIN value (4 ~ 12 digits)
        self.format_f4_PIN_lb = Label(format_f4, text="PIN value")
        self.format_f4_PIN_lb.grid(row=7, column=0, sticky=E)
        self.format_f4_PIN_txt = Entry(format_f4, font = "Courier 9", width=56)
        self.format_f4_PIN_txt.grid(row=7, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   RULER !
        self.format_f4_ruler_2 = Label(format_f4, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9",width=48)
        self.format_f4_ruler_2.grid(row=8, column=1, columnspan=3, padx=6, pady=1, sticky=W)

        #   0.5 PAN value (4 ~ 12 digits)
        self.format_f4_PAN_lb = Label(format_f4, text="PAN value")
        self.format_f4_PAN_lb.grid(row=9, column=0, sticky=E)
        self.format_f4_PAN_txt = Entry(format_f4, font="Courier 9", width=56)
        self.format_f4_PAN_txt.grid(row=9, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   rnd filling in the PIN field
        self.format_f4_rnd_field_lb = Label(format_f4, text="rnd field")
        self.format_f4_rnd_field_lb.grid(row=10, column=0, sticky=E)
        self.format_f4_rnd_field_txt = Entry(format_f4, font="Courier 9", width=56)
        self.format_f4_rnd_field_txt.grid(row=10, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   Separator !
        self.format_f4_separator = Label(format_f4, text="------------ Verify the plaintext & enciphered PINblock below ------------", font=("Helvetica", 10, "bold"),width=56)
        self.format_f4_separator.grid(row=11, column=0, columnspan=4, padx=5, pady=5, sticky=W)

        #   PIN field
        self.format_f4_PIN_field_lb = Label(format_f4, text="PIN field")
        self.format_f4_PIN_field_lb.grid(row=12, column=0, sticky=E)
        self.format_f4_PIN_field_txt = Text(format_f4, font="Courier 9", height=1, width=56)
        self.format_f4_PIN_field_txt.grid(row=12, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   PAN field
        self.format_f4_PAN_field_lb = Label(format_f4, text="PAN field")
        self.format_f4_PAN_field_lb.grid(row=13, column=0, sticky=E)
        self.format_f4_PAN_field_txt = Text(format_f4, font="Courier 9", height=1, width=56)
        self.format_f4_PAN_field_txt.grid(row=13, column=1, columnspan=3, padx=5, pady=5, sticky=W)

        #   0.6 Intermediate block A
        self.format_f4_interA_lb = Label(format_f4, text="Inter.\nblock A")
        self.format_f4_interA_lb.grid(row=14, column=0, sticky=E)
        self.format_f4_interA_txt = Text(format_f4, font = "Courier 9", height=2, width=56)
        self.format_f4_interA_txt.grid(row=14, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   0.7 Intermediate block B
        self.format_f4_interB_lb = Label(format_f4, text="Inter.\nblock B")
        self.format_f4_interB_lb.grid(row=15, column=0, sticky=E)
        self.format_f4_interB_txt = Text(format_f4, font = "Courier 9", height=2, width=56)
        self.format_f4_interB_txt.grid(row=15, column=1, columnspan=3, padx=5, pady=3, sticky=W)

        #   0.8 Output Data Plaintext Textbox
        #self.format_f4_pinBK_plain_lb = Label(format_f4, text=" Plaintext\npinblock")
        #self.format_f4_pinBK_plain_lb.grid(row=15, column=0, sticky=E)
        #self.format_f4_pinBK_plain_txt = Text(format_f4, font="Courier 9", height=2, width=56)
        #self.format_f4_pinBK_plain_txt.grid(row=15, column=1, columnspan=3, padx=5, pady=1, sticky=W)


        #   0.9 Output Data Enciphered Textbox
        self.format_f4_pinBK_cipher_lb = Label(format_f4, text="Enciphered\npinblock")
        self.format_f4_pinBK_cipher_lb.grid(row=16, column=0, sticky=E)
        self.format_f4_pinBK_cipher_txt = Text(format_f4, font="Courier 9", height=2, width=56)
        self.format_f4_pinBK_cipher_txt.grid(row=16, column=1, columnspan=3, padx=5, pady=1, sticky=W)

        #   0.10 Go Button
        self.format_f4_go_bt = Button(format_f4, text="Go!", width=10, bg='#D1FFBD', command=self.execution_F4)
        self.format_f4_go_bt.grid(row=17, column=3, padx=5, pady=5, sticky=E)

        
        #   8   About PinBox


def quit():
    global root
    root.quit()

update_timeText()
app = PinBox()
root.iconbitmap('C:/Python311/UL_logo_64.ico')
root.mainloop()
