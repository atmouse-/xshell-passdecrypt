import sys
import struct
import base64
import ConfigParser
import string
from collections import OrderedDict
import os
from os import linesep


class IniSettings:
    def __init__(self, filename, case_sensitive=1):
        self.filename = os.path.abspath(filename)
        if not os.path.isfile(filename):
            raise Exception("file not found")
        self.case_sensitive = case_sensitive
        self.settings = self.__loadConfig()

    def __loadConfig(self):
        config = OrderedDict()
        cp = ConfigParser.SafeConfigParser()
        if self.case_sensitive:
            # case-sensitive
            cp.optionxform = str
        else:
            pass
        cp.read(self.filename)
        for name in cp.sections():
            settings = OrderedDict()
            for opt in cp.options(name):
                settings[opt] = string.strip(cp.get(name, opt))
            config[name] = settings
        return config

    def reload(self):
        self.__loadConfig()

    def save(self):
        inifile = open(self.filename, 'wb')
        for group in self.settings.keys():
            inifile.write(linesep+"["+group+"]"+linesep)
            for key in self.settings[group].keys():
                inifile.write(key+"="+self.settings[group][key]+linesep)

    def set(self, group, key, value):
        if self.case_sensitive:
            pass
        else:
            key = string.lower(key)
        if not group in self.settings:
            self.settings[group] = {}
        self.settings[group][key] = value
        return True

    def get(self, group, key):
        if self.case_sensitive:
            pass
        else:
            key = string.lower(key)
        if not group in self.settings:
            return None
        return self.settings[group][key]

    def pop(self, group, key=''):
        assert group
        if not group in self.settings:
            return True
        if key:
            if not key in self.settings[group]:
                return True
            self.settings[group].pop(key)
        else:
            self.settings.pop(group)
        return True

    def set_dict(self, dict):
        for group in dict.keys():
            for key in dict[group].keys():
                self.settings[group][key] = dict[group][key]


srcmap = base64.b64decode("""\
uhyFBqY/DlV2q63KTQEF4qzqlyiRfnATknp0a+2lI7It2n01IM1mlBkrZdC5vN9s1rQsC+Q9uxjwCnw+
y+FoDNVDjC6/zoef21hhY7eP0oiJUPRbWdSQR/W1T1yN8cQH3Y6B+0tSzGQxzx+onTrcqcGnEkneRvjz
gu94U3kpWsL8D8D/mTNU8n+A7p7ZJBuWmwmEe16cOF2kbfezo6pXKneG9siuIjRx6RpBAFZzMouxTjD9
45UI4Ow8ForJoF8dFdNM/qElaR5nIcaTA0Um+i9gxzdR5xAU6LjRRG5CmOUNEcWv+Ttq2HIEsL5v12KD
dRcnQAJI6zY5okq2w72a5gI=""")
srcmap = list(srcmap)


def decrypt(src_enc):
    out = ''
    lmap = list(srcmap)
    i = 1
    ebx = struct.unpack('>B', '\x00')[0]
    ecx = struct.unpack('>B', lmap[i])[0]
    ebx = ((ebx % 256) + (ecx % 256)) % 256
    edx = struct.unpack('>B', lmap[ebx])[0]
    lmap[ebx] = ecx
    lmap[i] = struct.pack(">B", edx)

    for i in range(2, len(src_enc)+2):
        edx = ((edx % 256) + (ecx % 256)) % 256

        # PXOR mm2, mm0

        ecx = struct.unpack('>B', lmap[i])[0]
        # print lmap
        mm1 = lmap[edx]
        # print("got: " + repr(mm1))
        out += chr(struct.unpack(">B", src_enc[i-2])[0] ^ struct.unpack(">B", mm1)[0])

        # print "ADD BL,CL: ", hex(ebx), hex(ecx)
        ebx = ((ebx % 256) + (ecx % 256)) % 256
        # mm1 << i

        edx = struct.unpack('>B', lmap[ebx])[0]

        lmap[ebx] = struct.pack(">B", ecx)
        lmap[i] = struct.pack(">B", edx)
    return out


encrypt = decrypt


if __name__ == "__main__":
    try:
        walkdir = sys.argv[1]
    except:
        walkdir = ''
    if not walkdir:
        walkdir = os.path.join(os.environ["USERPROFILE"],
                                          "AppData",
                                          "Roaming",
                                          "NetSarang",
                                          "Xshell",
                                          "Sessions")
    for root, dirs, files in os.walk(walkdir):
        for f in files:
            filepath = os.path.join(root, f)
            if not f.endswith('.xsh'):
                continue
            sys.stdout.write(filepath[len(walkdir):])
            try:
                ini = IniSettings(filepath, case_sensitive=1)
                src_enc = base64.b64decode(ini.get("CONNECTION:AUTHENTICATION", "Password"))
                src_enc = list(src_enc)
                sys.stdout.write(': ')
                sys.stdout.write(decrypt(src_enc))
                sys.stdout.write('\n')
            except:
                sys.stdout.write('\n')
