"""
Extracting jpeg from binary data.
"""
import binascii

jpeg_signatures = [
    binascii.unhexlify(b'FFD8FFD8'),
    binascii.unhexlify(b'FFD8FFE0'),
    binascii.unhexlify(b'FFD8FFE1')
]

images = []
binary_path = "com.funeasylearn.german/res/raw/images.jpg"

with open(binary_path,"rb") as fp:
    fp.seek(0, 2)
    num_bytes = fp.tell()
    count = 0
    for i in xrange(num_bytes):
        fp.seek(i)
        one_byte = fp.read(1)
        if one_byte == binascii.unhexlify(b"FF"):
            # If byte matches FF, then read 3 more bytes and check jpeg signature
            t_byte = fp.read(3)
            i += 3
            current = (one_byte + t_byte)
            if current in jpeg_signatures:
                print "Found jpeg %d at %d" %(count, i-3)
                count += 1
                images.append(i-3)
                if len(images) == 2:
                    with open("tmp/"+str(images[0])+".jpg", "wb") as out:
                        fp.seek(images[0])
                        data = fp.read(images[1]-images[0])
                        out.write(data)
                    del images[0]
