__author__ = 'makpoc'


class CertWithFile():
    def __init__(self, cert, file):
        self.cert = cert
        self.file = file

    def get_cert(self):
        return self.cert

    def get_file(self):
        return self.file


class ChainNode():
    def __init__(self, cert_with_file):
        self.cert_with_file = cert_with_file
        self.children = []

    def add_child(self, child):
        self.children.append(child)

    def get_file(self):
        return self.cert_with_file.get_file()

    def get_certificate(self):
        return self.cert_with_file.get_cert()

    def get(self):
        return self.cert_with_file

    def get_children(self):
        return self.children