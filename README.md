# analyseAsn1
analyse Asn1 format data encoding by der or pem.

enviroment: python3

usage example:
[/Users/aaa]$ python3 ./analyseAsn1.py 1.txt pem
SequenceTag(nr=16, typ=32, cls=0):
    SequenceTag(nr=16, typ=32, cls=0):
        ObjectIdentifierTag(nr=6, typ=0, cls=0):1.2.840.113549.1.1.1
        NullTag(nr=5, typ=0, cls=0):
    BitStringTag(nr=3, typ=0, cls=0):
        SequenceTag(nr=16, typ=32, cls=0):
            IntegerTag(nr=2, typ=0, cls=0):0x0095abdfcff15f68b7a2c237b7d3d111463818a3393c8b3fbe1cf92efc14caf72c6cceaf89fe9dcc2c72624e53a10241091148fb32622f563bf903d5d850dffb13246898eedb5743a4b5a050e83231fabacc17e95a6dff09401678ce657ca55f6480432da30676927141505f37b76832836b22f421bd52028c8670915fd7c8640842166411e8ecece06241ecf40e472dc942de1bb7c785088b7116274552ef1549b0959ae8f9092d16d6415e23ae9c866f299c6715e42c05bb91bfe599c44ddb65b284bdfe00bb0d86352874cee85a681106c330a6b9544275d27a8b953419088fe9802e2a35634009fbbca7cdcc035cd5bd150c961b68a320bc2f2eda969fd5a5
            IntegerTag(nr=2, typ=0, cls=0):65537
