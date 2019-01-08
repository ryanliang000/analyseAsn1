#!/usr/bin/python
import asn1
import sys
import base64
import re

if (len(sys.argv) != 3):
    print("Useage: {} certfile pem/der)".format(sys.argv[0]))
    sys.exit(1)

def getTagDesc(tag):
    if (tag.cls == 0x80):
        return asn1.Classes(tag.cls).name + "[" + str(tag.nr) + "]"
    try:
        return asn1.Numbers(tag.nr).name + str(tag)
    except:
        return asn1.Types(tag.typ).name + str(tag)

der = "" 
if (len(sys.argv) == 3 and sys.argv[2] == 'der'):
    fd = open(sys.argv[1], 'rb')
    der = fd.read()
    fd.close()
else:
    fd = open(sys.argv[1])
    pem = fd.read()
    fd.close()
    pem = re.sub('[-]+[A-Z ]+[-]+\n','',pem) 
    der = base64.b64decode(pem)

def analyseAsn1(der, tab=''):
    decoder = asn1.Decoder()
    decoder.start(der)
    while(True):
        if (decoder.eof()):
            break;
        
        tag = decoder.peek()
        if (tag is None): break
        if (tag.cls == 0x80): #context to octstring 
            tag = asn1.Tag(4, tag.typ, tag.cls)
            tagReal, value = decoder.read(tag.nr)
        else:
            tagReal, value = decoder.read()

        print('\n{}{}:'.format(tab, getTagDesc(tagReal)), end='')
        if (value is None): continue

        isSubDecode = False;
        if (tag.typ != asn1.Types.Primitive.value):     #constructed
            isSubDecode = analyseAsn1(value, tab + "    ")
        elif (tag.cls == 0):        #Universal
            if (tag.nr == 4 and len(value) > 1 and value[0] == 0x30):      #ocstring
                isSubDecode = analyseAsn1(value, tab + "    ")
            elif (tag.nr == 3 and len(value) > 2 and value[0:2] == b'\x00\x30'):     #binary string
                isSubDecode = analyseAsn1(value[1:], tab + "    ")

        if (not isSubDecode):
            if (tag.nr in (3,4)):   #binarystring, octstring or big integer
                print('0x{}'.format(value.hex()), end='')
            elif (tag.nr == 2 and value.bit_length() > 64): #int 
                print('0x{}'.format(asn1.Encoder._encode_integer(value).hex()), end='')
            elif (tag.nr == 0x1e):  #unicodestring
                print(value.decode('utf8'), end='')
            elif (tag.nr == 0):
                print('0x{}'.format(value.hex()), end='')
            else:
                print(value if (value) else '', end='')
    return True;

analyseAsn1(der)
print("")
