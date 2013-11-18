__author__ = "makpoc"

import os
from os.path import expanduser
from Tkinter import *
import tkFileDialog
import ttk
import opensslwrapper


class simpeCertManagerGui(Tk):
    def __init__(self, parent, title):
        Tk.__init__(self, parent)
        self.parent = parent
        self.title(title)
        self.loadedcertificates = {}
        self.__init_main()
        self.__init_frames()
        self.__init_tree()
        self.__init_browser()
        self.__init_cert_management()

    def __init_main(self):
        self.geometry("+%d+%d" % (20, 20))
        self.grid()
        self.resizable(False, False)

    def __init_frames(self):
        self.frame = Frame(self.parent)
        self.leftframe = Frame(self.frame)
        self.rightframe = Frame(self.frame)
        self.frame.grid(column=0, row=0)
        self.leftframe.grid(column=0, row=0)
        self.rightframe.grid(column=1, row=0)

    def __init_browser(self):
        self.certlocation = StringVar(value=expanduser('~'))
        self.label = Label(self.leftframe, textvariable=self.certlocation)
        self.browseBtn = Button(self.leftframe, text="Browse...", command=self._opendialog)
        self.label.grid(padx=5, column=0, row=5, sticky=W)
        self.browseBtn.grid(padx=5, column=0, row=5, sticky=E)

    def __init_cert_management(self):
        self.generateCaBtn = Button(self.rightframe, text="Generate CA...", width=17,
                                    command=lambda: self.gen_new_cert(True))
        self.generateCertBtn = Button(self.rightframe, text="Generate certificate...", width=17,
                                      command=lambda: self.gen_new_cert(False))
        self.deleteCertBtn = Button(self.rightframe, text="Delete certificate...", width=17, command=self.deletecert)
        self.exportCertBtn = Button(self.rightframe, text="Export as p12...", width=17, command=self._dummy)
        self.detailsBtn = Button(self.rightframe, text="View Details...", width=17, command=self._dummy)
        self.generateCaBtn.grid(column=1, row=0, sticky=W)
        self.generateCertBtn.grid(column=1, row=1, sticky=W)
        self.deleteCertBtn.grid(column=1, row=2, sticky=W)
        self.exportCertBtn.grid(column=1, row=3, sticky=W)
        self.detailsBtn.grid(column=1, row=4, sticky=W)
        self.__toggle_buttons_state()

    def __init_tree(self):
        columns = ('Subject', 'Issuer', 'SANs')
        self.tree = ttk.Treeview(self.leftframe, selectmode="browse", columns=columns, height=26)
        self.tree.heading('#0', text='File')
        for index, column in enumerate(columns):
            self.tree.column(column, width=250)
            self.tree.heading('#%d' % (index + 1), text=column)

        self.tree.bind('<<TreeviewSelect>>', lambda event: self.__toggle_buttons_state())

        self.tree.grid(padx=5, column=0, rowspan=4, sticky=NW)

    def __toggle_buttons_state(self):
        self.exportCertBtn['state'] = self.generateCertBtn['state'] = self.deleteCertBtn['state'] = self.detailsBtn[
            'state'] = 'normal' if self.tree.selection() else 'disabled'

    def _dummy(self):
        pass

    def deletecert(self):
        try:
            os.remove(os.path.join(self.certlocation.get(), self.tree.item(self.tree.selection())['text']))
        except Exception as e:
            print '[*] Failed to delete certificate %s. %s' % (self.certlocation.get(), e)
        self._updateTree()
        self.__toggle_buttons_state()

    def gen_new_cert(self, isrootca):
        dialog = Toplevel(self)
        dialog.geometry(
            "+%d+%d" % (self.winfo_x() + (self.winfo_width() / 4), self.winfo_y() + (self.winfo_height() / 4)))
        selection = None
        if isrootca:
            textLbl = Label(dialog, text="Generate new ROOT CA certificate and key:")
        else:
            selection = self.tree.item(self.tree.selection())["text"]
            textLbl = Label(dialog, text="Generate new Interm CA and sign it using %s" % selection)

        subjectLbl = Label(dialog, text="Subject:")
        subjectEntry = Entry(dialog)
        subjectEntry.focus()

        genBtn = Button(dialog, text="Generate", width=17,
                        command=lambda: self._generate(dialog, selection, subjectEntry.get()))
        dialog.bind('<Return>', lambda event: self._generate(dialog, selection, subjectEntry.get()))

        textLbl.grid(pady=5, padx=2, column=0, row=0, sticky=N, columnspan=1)
        subjectLbl.grid(padx=2, column=0, row=2, sticky=W)
        subjectEntry.grid(column=0, row=2)
        genBtn.grid(pady=10, column=0, row=3)

        dialog.focus_set()
        dialog.grab_set()
        dialog.transient()

    def _generate(self, dialog, issuer_f, subject):
        subjectdict = {}
        for item in subject.replace(", ", ",").split(","):
            k, v = item.split("=")
            subjectdict[k] = v
        if not issuer_f or self.loadedcertificates[issuer_f] == subject:
            opensslwrapper.generate_ca(self.certlocation.get(), **subjectdict)
        else:
            opensslwrapper.generate_interm(self.certlocation.get(), self.loadedcertificates[issuer_f], **subjectdict)
        self._updateTree()
        dialog.destroy()

    def _opendialog(self):
        self.certlocation.set(
            tkFileDialog.askdirectory(parent=self.frame, title="Select certificate folder",
                                      initialdir=expanduser('~')))
        self._updateTree()

    def _updateTree(self):
        if not os.path.exists(self.certlocation.get()):
            return None
        existingitems = self.tree.get_children()
        for item in existingitems:
            self.tree.delete(item)

        self.loadedcertificates = opensslwrapper.loadcertificates(self.certlocation.get())
        if self.loadedcertificates:
            chains = opensslwrapper.construct_chains(self.loadedcertificates)

            for chain in chains:
                self._build_tree(chain, '')
            self._sort()
        else:
            print '[*] Folder %s does not contain valid certificates!' % self.certlocation

    def _build_tree(self, chain, parent):
        cert = chain.get().get_cert().get_certificate()
        subject = opensslwrapper.construct_subject_from_component(cert.get_subject().get_components())
        issuer = opensslwrapper.construct_subject_from_component(cert.get_issuer().get_components())
        item = self.tree.insert(parent, 'end', text=chain.get().get_file(), values=(subject, issuer, "TODO"), open=True)
        children = chain.get_children()
        if children:
            for child in children:
                self._build_tree(child, item)

    def _sort(self):
        l = [(self.tree.set(k, '1'), k) for k in self.tree.get_children('')]
        l.sort()

        # rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)


if __name__ == "__main__":
    app = simpeCertManagerGui(None, "Simple Certificate Manager")
    app.mainloop()
