from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#from moo import ECB_MOO, CBC_MOO, CFB_MOO, OFB_MOO, CTR_MOO 

def main():
    msg = b'thismessageisone'

    key = get_random_bytes(16)

    cipherECBtest = AES.new(key, AES.MODE_ECB)
    ciphertextTest = cipherECBtest.encrypt(msg)
    #print(ciphertextTest)
    for x in (cipherECBtest, ciphertextTest):
        print(x)

    # cipher = AES.new(key, AES.MODE_EAX) # test
    # cipherECB = AES.new(key, AES.MODE_ECB) # replace with my moo implementation later
    # cipherCBC = AES.new(key, AES.MODE_CBC) # replace with my moo implementation later
    # cipherCFB = AES.new(key, AES.MODE_CFB) # replace with my moo implementation later
    # cipherOFB = AES.new(key, AES.MODE_OFB) # replace with my moo implementation later
    # cipherCTR = AES.new(key, AES.MODE_CTR) # replace with my moo implementation later

    # ciphertext, tag = cipher.encrypt_and_digest(msg)
    # ciphertext1 = cipherECB.encrypt(msg)
    # ciphertext2 = cipherCBC.encrypt(msg)
    # ciphertext3 = cipherCFB.encrypt(msg)
    # ciphertext4 = cipherOFB.encrypt(msg)
    # #ciphertext5, tag1 = cipherCTR.encrypt(msg)

    # for x in (cipher.nonce, tag, ciphertext):
    #     print(x)
    
    # for x1 in (cipherECB, ciphertext1):
    #    print(x1)
    
    # for x2 in (cipherCBC, ciphertext2):
    #     print(x2)
    
    # for x3 in (cipherCFB, ciphertext3):
    #     print(x3)
    
    # for x4 in (cipherOFB, ciphertext4):
    #     print(x4)
    
    #for x5 in (cipherCTR.nonce, tag1, ciphertext5):
    #    print(x5)

if __name__ == "__main__":
    main()