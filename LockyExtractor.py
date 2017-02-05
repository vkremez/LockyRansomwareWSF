# Decodes Locky JSCRIPT loaders and obtains payload indicators of compromise (IOCs)
# Python3

import re
import base64

class LockyPayload():
    def __init__(self, jscript_file=None):
        if jscript_file:
            self._jscript = open(jscript_file,"r")
        else:
            self._jscript = None
        self._padding_word = None
        self._file_name = None
        self._xor_key = None
        self._payload_uri_1 = None
        self._payload_uri_2 = None
        self._payload_uri_3 = None
        self._extension = None

    def parse_lines(self):
        java_lines = filter(None, (line.rstrip() for line in self._jscript.readlines()))

        padding_pattern = 'this.replace('
        eval_pattern = 'eval('
        try_pattern = 'try{'

        eval_activate = False
        try_activate = False

        if self._jscript:
            for line in java_lines:
                if padding_pattern in line:
                    line = "".join(line.split())
                    self._padding_word = line.split('/')[1]

                elif eval_pattern in line:

                    eval_activate = True

                elif eval_activate is True:
                    if self._file_name is None:
                        self._file_name = re.findall('"[^"]+"', line)[0].replace('"', "") + ".dll"
                    elif self._xor_key is None:
                        self._xor_key = re.findall('"[^"]+"', line)[0].replace('"', "")
                    elif try_pattern in line:
                        try_activate = True
                        eval_activate = False
                    else:

                        triple_line = re.findall('"[^"]+"', line)
                        if len(triple_line) == 3:
                            self._payload_uri_1 = base64.b64decode(
                                triple_line[0].replace('"', "").replace(self._padding_word, "")).decode('utf-8')
                            self._payload_uri_2 = base64.b64decode(
                                triple_line[1].replace('"', "").replace(self._padding_word, "")).decode('utf-8')
                            self._payload_uri_3 = base64.b64decode(
                                triple_line[2].replace('"', "").replace(self._padding_word, "")).decode('utf-8')
                elif try_activate is True:
                    self._extension = re.findall('"[^"]+"', line)[0].replace('"', "")
                    try_activate = False
                else:
                    pass
            self._payload_uri_1 += self._extension
            self._payload_uri_2 += self._extension
            self._payload_uri_3 += self._extension
        else:
            print("No jscript file loaded")

    def file(self):
        return self._file_name

    def xor_key(self):
        return self._xor_key

    def pay_load_1(self):
        return self._payload_uri_1

    def pay_load_2(self):
        return self._payload_uri_2

    def pay_load_3(self):
        return self._payload_uri_2

    def dictionary(self):
        data_dict = {
            'File Name': self._file_name,
            'XOR Key': self._xor_key,
            'URI 1': self._payload_uri_1,
            'URI 2': self._payload_uri_2,
            'URI 3': self._payload_uri_3,
            'Extension': self._extension,
        }
        return data_dict

if __name__ == "__main__":
    name = input("Enter jscript file name with jscript extension: ") 
    LP = LockyPayload(jscript_file=name)
    LP.parse_lines()
    print(LP.dictionary())
