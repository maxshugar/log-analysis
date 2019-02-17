from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import os
import re
from itertools import groupby

def get_bin_attempts():
    file  = open('auth.log', 'r').read() #open auth.log in read only mode point pointed to by file
    count = file.count("Failed password for bin")#count the number of occurences the string of interest occurs
    configfile.delete('1.0', END)#clear the text box
    configfile.insert(INSERT, "Failed login attempts for user bin: %d" % count)#insert text into text box

def run_blacklists():
    def grab_ip(file): #create a function called grap_ip
        with open("blacklisttips.txt", "w") as text_file:#create a text file - write mode
                    text_file.write("")#begin writing to the text file
        occurrence = {}#create an empty dictionary to hold the number of matched strings
        with open (file) as file:#open file
            for ip in file:#for each line in the file
                selected_data = re.findall(r'Failed password for .*from* .*(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})*', ip)#find attack string
                for data in selected_data: #for each line in data
                    ip_s = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', data)#parse ip from attack
                    for ipaddr in ip_s: #for each ip in data
                        if ipaddr in occurrence:#if the ip is a key in occurence
                            occurrence[ipaddr] = occurrence[ipaddr] + 1 #add 1 to the value of the key
                        else:#if the ip is not a key in occurence
                            occurrence[ipaddr] = 1 #make the value of the key is equal to 1
            for key, value in occurrence.items():#for the keys and values in occurence
                if (value > 30): #if the value is greater than 30
                    with open("blacklisttips.txt", "a") as text_file: #open blacklisttips.txt
                        text_file.write("%s had %d failed login attempts\n" % (key, value)) #store the key and value in the text file
            return None
    grab_ip('auth.log')#call function
    configfile.delete('1.0', END)#clear the text box
    with open('blacklisttips.txt', 'r') as f:#open blacklisttips.txt in read mode
        configfile.insert(INSERT, f.read()) # insert text from text file into text box

def get_attack_frequency():
    attacks = [] #list to store the attacks
    counts = dict()#dictionary
    with open("auth.log") as f: #open auth.log
        for line in f:#for each line in auth.log
            if "Failed password for" in line: #if text is in line
                attacks.append(line[:9])#append first 9 characters of line to list
    for i in attacks: #for each item in attacks
        counts[i] = counts.get(i, 0) + 1#increment the value of each key in the dictionary. 0 is the default value.
    configfile.delete('1.0', END)#clear the text box
    for key, value in counts.items():#for keys and values in dicitonary
        month, day, hour = key[0:3], key[4:6], key[7:9]#initialise varaibles
        configfile.insert(INSERT, "There were %d failed login attempts made on %s%s between %s:00:00 and %s:59:99\n" % (value, month, day, hour, hour))#insert data into text box

def get_attack_ip():
    attacks = (line for line in open('auth.log', 'r') if "Failed password for" in line)#store lines that include string of interest
    configfile.delete('1.0', END)#clear the text box
    for key, group in groupby(attacks, key = lambda z: z[:9] + re.search('from(.+?) ', z).group()):#group by the first nine characters of the
        month, day, hour, ip = key[0:3], key[4:6], key[7:9], key[14:]#initialise the month day and hour variables to respective characters
        configfile.insert(INSERT, "There were %d failed login attempts made from %son %s%s between %s:00:00 and %s:59:99\n" % (len(list(group)), ip, month, day, hour, hour))#insert data into text box


def compare_files():
    configfile.delete('1.0', END)#clear the text box
    webserver_ip = {}#create an empty dictionary to hold the number of matched strings
    with open ('access.log') as file:#open file
            for line in file:#for each line in the file
                temp = r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'#store regualar expression template for IP address
                selected_data = re.findall(temp, line)#find attack string
                for ip in selected_data:#for each ip
                    if ip in webserver_ip:#if ip is already a key in the dictionary
                        webserver_ip[ip] = webserver_ip[ip] + 1#add +1 to the key's value
                    else:#if ip is not already a key in the dictionary
                        webserver_ip[ip] = 1 #keys value is equal to 1
    for key, value in webserver_ip.items():#for each key and value in the dictionary
                with open ('auth.log') as file:#open auth.log
                    for line in file:#for each line in auth.log
                        if re.findall('(.+){0}(.+)'.format(key), line):#if the ip in the dicitionary appears in auth.log line
                            x = line.split('Accepted password for ')#split the line at string
                            y = x[1].split(' ')#split the line at space
                            username = y[0]#username initialisation
                            correlated_line_auth = line#line of interest
    with open ('access.log') as file:#open file
            for line in file:#for each line in the file
                if re.findall(username, line):#if username appears in access.log
                    x = line.split('username=jsmith&password=')#split the line at string
                    y = x[1].split(' ')#split the line at space
                    password = y[0]#password initialisation
                    correlated_line_access = line#line of interest
    with open("correlation.txt", "w") as text_file:#create a text file - write mode
        text_file.write("Username: %s Password: %s\n\n" % (username, password))#write to the text file
        text_file.write('Auth.log: %s\n' % correlated_line_auth)#write to the text file
        text_file.write('Access.log: %s\n' % correlated_line_access)#write to the text file
    with open('correlation.txt', 'r') as f:#open text file in read only mode
        configfile.insert(INSERT, f.read())#insert contents of text file into text box
        
rw = Tk()#initailaise Tk

rw.title("Text File Parser")#set the title

configfile = Text(wrap=WORD, width=60, height= 10)#set the width and height of a text box
configfile.pack(fill=X, padx=10, pady=10)#pack it
configfile.insert(INSERT, 'Welcome to the text file parser GUI.')#insert text into the textbox

btn1=ttk.Button(rw, text="Display the number of failed login attempts for bin.")#insert title into button
btn1.pack(fill=X, padx=10, pady=10)#pack it
btn1.config(command=get_bin_attempts)#set function

btn2=ttk.Button(rw, text="Create and display blacklisttips.txt")#insert title into button
btn2.pack(fill=X, padx=10, pady=10)#pack it
btn2.config(command=run_blacklists)#set function

btn3=ttk.Button(rw, text="Calculate the number of attacks per hour.")#insert title into button
btn3.pack(fill=X, padx=10, pady=10)#pack it
btn3.config(command=get_attack_frequency)#set function

btn4=ttk.Button(rw, text="Calculate the number of attacks per hour per IP.")#insert title into button
btn4.pack(fill=X, padx=10, pady=10)#pack it
btn4.config(command=get_attack_ip)#set function

btn5=ttk.Button(rw, text="Detect Correllation")#insert title into button
btn5.pack(fill=X, padx=10, pady=10)#pack it
btn5.config(command=compare_files)#set function

