import os
import tkinter.messagebox
from tkinter import filedialog,messagebox

import networkx as nx
import geoip2.database

from pyvis.network import Network

import matplotlib.pyplot as plt
import pandas.core.frame

from pandastable import *
from time import sleep
import pandas as pd
import tkinter as tk
import customtkinter as ctk
import pathlib
import threading




#err = open("errors.log",'a')
#sys.stderr = err
asset= pathlib.Path(__file__).parent / "assets/asset.png"

ctk.set_appearance_mode("System")  # Modes: system (default), light, dark
ctk.set_default_color_theme("dark-blue") #["blue", "green", "dark-blue", "sweetkind"]

def show_error_tk(content,title="Error"):
    tk.messagebox.showinfo(title,content)
def reduce_str(s:str,max)->str:
    l: list = []
    if len(s) < max:
        return s
    else:
        for i in s:
            l.append(i)
        while True:
            ind = round(len(l) / 2)
            l.pop(ind)
            if len(l) < max:
                break
        ind = round((len(l) / 2) - 1)
        l[ind] = '.'
        l[ind + 1] = '.'
        l[ind + 2] = '.'
        return str(''.join(l))

def make_thread_from(func):
    thr = threading.Thread(target=func,daemon=True)
    thr.start()

class pandas_to_tk_table(ctk.CTkFrame):
    def __init__(self, parent, input_file_path,h,w, editable=True, enable_menus=False):
        super().__init__(parent)
        if  type(input_file_path) == pathlib.WindowsPath :
            self.table = Table(self, showtoolbar=False, showstatusbar=False, height=h, width=w)
            self.table.importCSV(input_file_path)
        else:
            self.table = Table(self,dataframe=input_file_path, showtoolbar=False, showstatusbar=False, height=h, width=w)

        self.table.show()
        # self.table.addColumn('Current Status')
        self.table.autoResizeColumns()
def start_table(master,inp,h=400,w=400):
    app = pandas_to_tk_table(master, inp,h=h,w=w)
    app.place(bordermode=INSIDE, x=0, y=0)
    df = app.table.model.df

#MAIN CLASS ------------------------------------------------------------------------------------------------------------------
class mainApp():
    def __init__(self,master):
        #Variables
        self.data_file = None
        self.INPUT_FILE = pathlib.Path('-')
        self.INPUT_FILE_STATUS: str = 'File : ' + str(self.INPUT_FILE)
        #master
        self.master = master
        master.geometry("410x320")  #"800x600"
        master.title("Network Analyzer")
        master.configure(bg="#202020")
        master.resizable(False, False)
        #tabs
        self.TABS_DIM = (int(560/2), int(785/2)) #560, 785
        self.tab_view = ctk.CTkTabview(master, height=self.TABS_DIM[0], width=self.TABS_DIM[1], command=self.manage_tab_click)
        self.tab_view.grid(row=0,column=0,columnspan=4,padx=8)
        self.tab_1 = self.tab_view.add('Show Data')
        self.tab_2 = self.tab_view.add('Show Graph')
        self.tab_4 = self.tab_view.add('Suspect')
        self.tab_3 = self.tab_view.add('Extra')
        #open file button
        self.button_open = ctk.CTkButton(master=master, text="Open File", command=self.btn_open_file)
        #file label
        self.label_file_txt = tk.StringVar(master=master,value=self.INPUT_FILE_STATUS)
        self.label_file = ctk.CTkLabel(master=master,textvariable=self.label_file_txt,wraplength=500)
        #grid manager
        self.button_open.grid(row=1, column=3, columnspan=1,pady=8,padx=10,sticky=tk.E)
        self.label_file.grid(row=1,column=0,rowspan=2,columnspan=3,pady=8,padx=10,sticky=tk.W)
        #Filling tabs
        tab_n3(self.tab_3, self.tab_view, self.TABS_DIM)
        tab_ShowData(self.tab_1,self, self.TABS_DIM)
        tab_GraphData(self.tab_2,self, self.TABS_DIM)
        tab_sus(self.tab_4,self, self.TABS_DIM)

        #Open capture file on startup
        self.btn_open_file()
    #self.check_if_file_opened()
    def check_if_file_opened(self):
        if self.INPUT_FILE.exists(): return False
        tk.messagebox.showwarning("No CSV File provided.",
                                  "Please upload a valid CSV file of Wireshark export format.")
        return True
    #Callbacks
    def btn_open_file(self):
        inp = tk.filedialog.askopenfilename(filetypes=(("CSV files", "*.csv"),("All files", "*.*")),
                                            title="Open a WireShark network packet capture log file")
        if inp == '':
            return
        self.INPUT_FILE = pathlib.Path(inp)
        self.INPUT_FILE_STATUS = 'File : ' + reduce_str(str(self.INPUT_FILE.name),35)
        self.label_file_txt.set(value=self.INPUT_FILE_STATUS)
        try:
            self.data_file = None
            self.data_file = pd.read_csv(self.INPUT_FILE)
        except FileNotFoundError:
            tk.messagebox.showwarning("ERROR"," FILE NOT FOUND. Enter valid file path.")
        except PermissionError:
            tk.messagebox.showwarning("Permission Error","Admin privileges required to run this command. Please try again.")
        except OSError:
            tk.messagebox.showwarning("ERROR"," Invalid argument. Please enter without quote marks.")
        if not self.check_if_csv_valid():
            self.data_file = None
            self.INPUT_FILE = pathlib.Path('-')
            self.INPUT_FILE_STATUS = 'File : ' + str(self.INPUT_FILE.name)
            self.label_file_txt.set(value=self.INPUT_FILE_STATUS)
            tk.messagebox.showwarning("Invalid CSV Format provided.","Please upload a valid CSV file of Wireshark export format.")
            return
        self.data_file = self.data_file.drop(['No.', 'Time', 'Length'], axis=1)
        #print(self.data_file)

    def check_if_csv_valid(self,df=None):
        columns = self.data_file.columns
        valid_col = ['No.', 'Time', 'Length','Source','Destination','Protocol','Info']
        print('nb of column : ',self.data_file.shape[1])
        for i in valid_col:
            if i not in columns:
                return False
        return True

    def manage_tab_click(self):
        #print('clicked : ',self.tab_view.get())
        pass
#CLASS ENDS ---------------------------------------------------------

class tab_ShowData():
    def __init__(self,master_tab,
                 mainapp : mainApp,
                 tabs_dimension):
        self.TABS_DIM = tabs_dimension
        self.tab_view = mainapp.tab_view
        self.master = master_tab
        self.mainapp = mainapp
        # frame
        self.frame = ctk.CTkFrame(master=self.master, height=self.tab_view.cget('height'),width=self.tab_view.cget('width')-30)
        self.frame.pack(padx=5)
        # Create buttons
        self.list_btn = {
            '1': 'Show All',
            '2': 'Show source and counts',
            '3': 'Show destination and counts',
            '4': 'Show protocols and counts',
            '5': ' Show all traffic of a protocol'
        }
        self.TK_list_btn = []
        self.TK_list_btn_func = []
        for i in self.list_btn.keys():
            indx = i
            f = lambda id=i: self.showdata(mainapp.data_file,sub_option=int(id))
            self.TK_list_btn_func.append(f)
            x = ctk.CTkButton(master=self.frame, text=self.list_btn.get(i), command=f)
            x.pack(padx=10,pady=5)
            self.TK_list_btn.append(x)


        #Filter button test
        self.filter_btn = ctk.CTkButton(master=self.frame, text="Filter", command=self.filter_popup)
        self.filter_btn.pack(padx=10, pady=5)


    def filter_data(self,column = '',value=''):
        if column == 'Protocol':
            self.mainapp.data_file =  self.mainapp.data_file[self.mainapp.data_file.Protocol != value]
        if column == 'Source':
            self.mainapp.data_file = self.mainapp.data_file[self.mainapp.data_file.Source != value]
        if column == 'Destination':
            self.mainapp.data_file = self.mainapp.data_file[self.mainapp.data_file.Destination != value]
    def filter_popup(self):
        if(self.mainapp.check_if_file_opened()):return
        def apply_cmd(sel,main):
            list_s = main.get_checked(1)
            list_d = main.get_checked(2)
            list_p = main.get_checked(3)
            print(list_p,list_d,list_s)
            for p in list_p:
                sel.filter_data(column='Protocol',value=p)
            for s in list_s:
                sel.filter_data(column='Source',value=s)
            for d in list_d:
                sel.filter_data(column='Destination',value=d)
            tkinter.messagebox.showinfo('Done','Data filtered succesfully !')
            main.parent.destroy()

        data_file = self.mainapp.data_file
        newWindow = ctk.CTkToplevel(self.frame)
        newWindow.title("Filter Data")
        newWindow.geometry("730x320+1000+100")
        newWindow.maxsize(730,320)

        list1 = data_file['Source'].unique()
        list2 = data_file['Destination'].unique()
        list3 = data_file['Protocol'].unique()
        main = Filter_option_frame(newWindow,list1,list2,list3)
        main.pack(side="top", fill="both", expand=True)

        main.apply_button.configure(command=lambda : apply_cmd(self,main))

###
    class InputPopup(ctk.CTkToplevel):
        def __init__(self, parent,title, choices):
            super().__init__(parent)
            self.title(title)
            #Choices box
            self.var = ctk.StringVar()
            self.listbox = ctk.CTkOptionMenu(self,values=choices,variable=self.var)
            self.listbox.pack(pady=5)
            #Confirm button
            self.btn = ctk.CTkButton(self, text="Confirm selection", command=self.select)
            self.btn.pack(pady=5)
            self.selection = None

        def select(self):
            self.selection = self.listbox.get()
            self.destroy()

        def show(self):
            self.deiconify()
            self.wm_protocol("WM_DELETE_WINDOW", self.destroy)
            self.wait_window(self)
            return self.selection

    def get_InputPopup(self,title,choices)->str:
        popup = self.InputPopup(self.frame,title, choices)
        result = popup.show()
        return result
###
    def get_input_from_listbar(self,df=None,choice=[]):
        ret = self.get_InputPopup('Choose', choices=choice)
        print('input from list bar =', ret)
        return ret
    
        x= [200,200]
    def display_table(self,file=None,hxw=(200,500),offset=(1000,100)):
        h,w = hxw
        x,y=offset
        newWindow = ctk.CTkToplevel(self.frame)
        newWindow.title("Data Table")
        newWindow.geometry(f"{w}x{h}+{x}+{y}")
        newWindow.minsize(w,h)
        start_table(newWindow,file,h=h-50,w=w-50)

    '''
    def display_table(self,file):
        newWindow = ctk.CTkToplevel(self.frame)
        newWindow.title("")
        newWindow.geometry("200x200+1000+100")
        newWindow.maxsize(520, 500)
        start_table(newWindow,file,h=450,w=450)
    '''

    def showdata(self,data_file,sub_option):
        if (self.mainapp.check_if_file_opened()): return
        #tk.messagebox.showinfo("Good",f'Pressed button number {sub_option}')
        if (sub_option == 1):
            try:
                #filtering ==>filtered_df = df.loc[df['Protocol'] == TCP | MDNS]
                self.display_table(self.mainapp.INPUT_FILE,hxw=(200,900))

            except KeyError:
                tk.messagebox.showwarning("Invalid CSV Format provided.",
                                          "Please upload a valid CSV file of Wireshark export format.")
        elif (sub_option == 2):
            try:
                sources = data_file.groupby(
                    "Source").Source.count()  # groups the csv data by the 'Source' filter and sorts them by their count
                s_df = pd.DataFrame({'Sources':sources.sort_values().index, 'Count':sources.sort_values().values})
                self.display_table(s_df)
            except KeyError:
                tk.messagebox.showwarning("Invalid CSV Format provided.",
                                          "Please upload a valid CSV file of Wireshark export format.")
        elif (sub_option == 3):
            try:
                dest = data_file.groupby(
                    "Destination").Destination.count()  # groups the csv data by the 'Destination' filter and sorts them by their count
                d_df = pd.DataFrame({'Destination':dest.sort_values().index, 'Count':dest.sort_values().values})
                self.display_table(d_df)
            except KeyError:
                tk.messagebox.showwarning("Invalid CSV Format provided.",
                                          "Please upload a valid CSV file of Wireshark export format.")
        elif (sub_option == 4):
            try:
                protocol = data_file.groupby(
                    "Protocol").Protocol.count()  # groups the csv data by the 'Protocol' filter and sorts them by their count
                p_df = pd.DataFrame({'Protocol ': protocol .sort_values().index, 'Count': protocol .sort_values().values})
                self.display_table(p_df)
            except KeyError:
                tk.messagebox.showwarning("Invalid CSV Format provided.",
                                          "Please upload a valid CSV file of Wireshark export format.")
        elif (sub_option == 5):
            try:
                unique_values = data_file['Protocol'].unique()
                ProtoSearch = self.get_input_from_listbar(choice=unique_values)
                pd.set_option('display.max_rows', 500)
                data = data_file.loc[data_file['Protocol'] == ProtoSearch, ["Source", "Destination", "Protocol"]]
                print(data)
                self.display_table(data)
                pd.set_option('display.max_rows', 10)
            except KeyError:
                tk.messagebox.showwarning("Invalid CSV Format provided.",
                                          "Please upload a valid CSV file of Wireshark export format.")
#fiter tab class
class ScrollableCheckBoxFrame(ctk.CTkScrollableFrame):
    def __init__(self, master, item_list, command=None, **kwargs):
        super().__init__(master, **kwargs)

        self.command = command
        self.checkbox_list = []
        for i, item in enumerate(item_list):
            self.add_item(item)

    def add_item(self, item):
        checkbox = ctk.CTkCheckBox(self, text=item,fg_color='red')
        if self.command is not None:
            checkbox.configure(command=self.command)
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 10))
        self.checkbox_list.append(checkbox)

    def remove_item(self, item):
        for checkbox in self.checkbox_list:
            if item == checkbox.cget("text"):
                checkbox.destroy()
                self.checkbox_list.remove(checkbox)
                return

    def get_checked_items(self):
        return [checkbox.cget("text") for checkbox in self.checkbox_list if checkbox.get() == 1]



class Filter_option_frame(ctk.CTkFrame):
    def __init__(self, parent,list1:list,list2:list,list3:list, *args, **kwargs):
        ctk.CTkFrame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.items = ['item1',
                      'item2',
                      'item3'
        ]
        self.grid_rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

        #
        self.label_1 = ctk.CTkLabel(self,text='Source').grid(row=0,column=0,padx=5,pady=1,sticky='ns')
        self.label_2 = ctk.CTkLabel(self, text='Destination').grid(row=0,column=1,padx=5,pady=1,sticky='ns')
        self.label_2 = ctk.CTkLabel(self, text='Protocols').grid(row=0,column=2,padx=5,pady=1,sticky='ns')
        list1.sort()
        list2.sort()
        list3.sort()
        #Scrollable Frames
        self.scrol_frame1 = ScrollableCheckBoxFrame(master=self,item_list=list1,command=self.cb)
        self.scrol_frame1.grid(row=1,column=0,padx=5,pady=5,sticky='ns')
        self.scrol_frame2 = ScrollableCheckBoxFrame(master=self,item_list=list2,command=self.cb)
        self.scrol_frame2.grid(row=1,column=1,padx=5,pady=5,sticky='ns')
        self.scrol_frame3 = ScrollableCheckBoxFrame(master=self,item_list=list3,command=self.cb)
        self.scrol_frame3.grid(row=1,column=2,padx=5,pady=5,sticky='ns')
        self.apply_button = ctk.CTkButton(self, text='Apply')
        self.apply_button.grid(row=2, column=1, padx=5, pady=5, sticky='ns')
        #

    def cb(self):
        print(f"Checked items : {self.scrol_frame1.get_checked_items()}")

    def get_checked(self,i:int)->list:
        if i == 1:
            return self.scrol_frame1.get_checked_items()
        if i == 2:
            return self.scrol_frame2.get_checked_items()
        if i == 3:
            return self.scrol_frame3.get_checked_items()

##

class tab_GraphData():
    def __init__(self,master_tab,
                 mainapp : mainApp,
                 tabs_dimension):
        self.TABS_DIM = tabs_dimension
        self.tab_view = mainapp.tab_view
        self.master = master_tab
        self.mainapp = mainapp
        # frame
        self.frame = ctk.CTkFrame(master=self.master, height=self.tab_view.cget('height'),width=self.tab_view.cget('width')-30)
        self.frame.pack(padx=5)
        # Create buttons
        self.list_btn = {
            '1': 'Display network map based on traffic',
            '2': 'Display bar graph based on protocol'
        }
        #button 1
        self.btn_1_cmd = lambda id=1: self.graphdata(mainapp.data_file,1)
        self.btn_1 = ctk.CTkButton(master=self.frame, text=self.list_btn.get('1'), command=self.btn_1_cmd)
        self.btn_1.pack(padx=10, pady=5)
        #radio button
        self.radio_var = ctk.IntVar(value=1)
        self.rad_frame = ctk.CTkFrame(master=self.frame)
        self.radiobutton_1 = ctk.CTkRadioButton(master=self.rad_frame, text="Interactive", variable=self.radio_var,
                                                value=1)
        self.radiobutton_2 = ctk.CTkRadioButton(master=self.rad_frame, text="Image", variable=self.radio_var, value=2)
        self.rad_frame.pack()
        self.radiobutton_1.pack(padx=10, pady=5, side=ctk.RIGHT)
        self.radiobutton_2.pack(padx=10, pady=5, side=ctk.RIGHT)
        #button 2
        self.btn_2_cmd = lambda id=2: self.graphdata(mainapp.data_file,2)
        self.btn_2 = ctk.CTkButton(master=self.frame, text=self.list_btn.get('2'), command=self.btn_2_cmd)
        self.btn_2.pack(padx=10, pady=5)


    def graphdata(self,df=None,sub_option=1):
        if (self.mainapp.check_if_file_opened()): return
        #??
        df = df
        #choice
        if sub_option == 1:
            if self.radio_var.get() == 1:#interactive
                x = nx.from_pandas_edgelist(df, source="Source", target="Destination",edge_attr=True)  # file and other attributes mentioned and stored in network variable.
                G = nx.DiGraph()
                G.add_nodes_from(x.nodes())
                G.add_edges_from(x.edges())
                # Plot with pyvis
                net = Network(directed=True, select_menu=True, filter_menu=True, )
                net.show_buttons()
                net.from_nx(G)  # Create directly from nx graph
                net.show('test.html', notebook=False)
                pass
            elif self.radio_var.get() == 2:#image
                network = nx.from_pandas_edgelist(df, source="Source", target="Destination", edge_attr=True)
                nx.draw_circular(network,
                                 with_labels=True)  # network map is drawn with the connections made from the network variable.
                # Network map is plotted (on a new window if running from terminal)
                plt.show()
        if sub_option == 2:
            protocol = df.groupby("Protocol").Protocol.count()
            x = list(protocol.index)  # x is the mlist of protocols
            y = list(protocol.values)  # y is the mlist of counts of the protocols
            plt.bar(x, y, width=0.5, color='red')
            plt.plot(x, y, marker='o', color='black')
            plt.xlabel('Protocol')
            plt.ylabel('Communications')
            plt.title('No. of Communications per Protocol')
            plt.show()  # plots the bar graph
        if sub_option == 3:
            pass


class tab_n3():
    def __init__(self,master_tab,master_tab_parent,tabs_dimension):
        self.TABS_DIM = tabs_dimension
        self.tab_view = master_tab_parent
        self.master = master_tab
        # frame_1
        self.frame_1 = ctk.CTkFrame(master=self.master, height=self.tab_view.cget('height'),
                                    width=self.tab_view.cget('width'))
        self.frame_1.pack()
        # TAB n°1
        # Create input field and label
        self.input_label = ctk.CTkLabel(self.frame_1, text="Enter program input:")
        self.input_label.pack()
        self.input_field_text = tk.StringVar()
        self.input_field = ctk.CTkEntry(self.frame_1, width=300, textvariable=self.input_field_text)
        self.input_field.bind('<Return>', command=self.send_button_cmd)
        self.input_field.pack()
        # Create button to execute program
        self.execute_button = ctk.CTkButton(self.frame_1, text="Execute", command=self.send_button_cmd)
        self.execute_button.pack()
        # Output label
        self.output_label = ctk.CTkLabel(self.frame_1, text="Program Output:")
        self.output_label.pack()
        self.output_text = ctk.CTkTextbox(self.frame_1, width=self.TABS_DIM[1] - 50, height=self.TABS_DIM[0] - 180)
        self.output_text.pack(padx=5, pady=5)


        self.output_text.insert('0.0',text="Doesn't do anything yet...")
        #

    def send_button_cmd(self, keypress=None):
        #print(self.input_field_text.get())
        #print(keypress)
        tk.messagebox.showinfo("Response ",f"You said : {self.input_field_text.get()}")
        self.input_field_text.set('')


class tab_sus():
    def __init__(self, master_tab,
                 mainapp: mainApp,
                 tabs_dimension):
        self.TABS_DIM = tabs_dimension
        self.tab_view = mainapp.tab_view
        self.master = master_tab
        self.mainapp = mainapp
        # frame
        self.frame = ctk.CTkFrame(master=self.master, height=self.tab_view.cget('height'),
                                  width=self.tab_view.cget('width') - 30)
        self.frame.pack(padx=5)
        #widgets
        self.entry_txt = ctk.StringVar()
        self.entry = ctk.CTkEntry(master=self.frame,textvariable=self.entry_txt)
        self.entry.pack(padx=5,pady=5)
        self.button_1 = ctk.CTkButton(master=self.frame,text="Go",command= lambda:self.suspect(self.mainapp.data_file))
        self.button_1.pack(padx=5,pady=5)

    x= [200,200]
    def display_table(self,file=None,hxw=(200,500),offset=(1000,100)):
        h,w = hxw
        x,y=offset
        newWindow = ctk.CTkToplevel(self.frame)
        newWindow.title("Data Table :")
        newWindow.geometry(f"{w}x{h}+{x}+{y}")
        newWindow.minsize(w,h)
        start_table(newWindow,file,h=h-50,w=w-50)

    def suspect(self,data_file=None,option=1):
        if (self.mainapp.check_if_file_opened()): return
        suspect_ad = self.entry_txt.get()
        print("Suspect loaded\n")
        
        # Suspect source and destination connection information is grapped and stored in two different variable and printed.
        suspect_source_info = data_file.loc[data_file[
                                                "Source"] == suspect_ad]  # takes the data from the captured file and cross-checks the suspect's connections as source
        suspect_dest_info = data_file.loc[data_file[
                                              "Destination"] == suspect_ad]  # takes the data from the captured file and cross-checks the suspect's connections as destination
        if suspect_dest_info.empty & suspect_source_info.empty:
            show_error_tk("Suspect not in network. Please try again.")
            return
            
        # loading network map data 
        network_s = nx.from_pandas_edgelist(suspect_source_info, source="Source", target="Destination", edge_attr=True)
        network_d = nx.from_pandas_edgelist(suspect_dest_info, source="Source", target="Destination", edge_attr=True)

        self.display_table(suspect_source_info,hxw=(200,500),offset=(600,100))
        self.display_table(suspect_dest_info,hxw=(200,500),offset=(600,100+250))
        try:
            plt.clf()
            pos = nx.spring_layout(network_s)  # the spring_layour positions nodes using Fruchterman-Reingold force-directed algorithm
            # Safe networks marked isolated and with green colour and other parameters
            nx.draw(network_s, pos, node_color="green", node_size=300, with_labels=True)
            # Suspect marked in red by program and larger size to show prominence
            options = {"node_size": 1000, "node_color": "r"}
            nx.draw_networkx_nodes(network_s, pos, nodelist=[suspect_ad], **options)
            #plt.savefig(fname = tk.filedialog.asksaveasfilename(confirmoverwrite=True,defaultextension='pdf') , dpi=150)
            plt.show()  # Network map is plotted (on a new window if running from terminal)
        except nx.exception.NetworkXError:
            show_error_tk("Suspect not in network. Please try again.")
        try:
            plt.clf()
            pos = nx.spring_layout(network_d)  # the spring_layour positions nodes using Fruchterman-Reingold force-directed algorithm
            # Safe networks marked isolated and with green colour and other parameters
            nx.draw(network_d, pos, node_color="green", node_size=300, with_labels=True)
            # Suspect marked in red by program and larger size to show prominence
            options = {"node_size": 1000, "node_color": "r"}
            nx.draw_networkx_nodes(network_d, pos, nodelist=[suspect_ad], **options)
            #plt.savefig(fname = tk.filedialog.asksaveasfilename(confirmoverwrite=True,defaultextension='pdf') , dpi=150)
            plt.show()  # Network map is plotted (on a new window if running from terminal)
        except nx.exception.NetworkXError:
            show_error_tk("Suspect not in network. Please try again.")


def main():
    root = ctk.CTk()
    app = mainApp(root)
    root.mainloop()


if __name__ == "__main__" :
    #main
    main()
