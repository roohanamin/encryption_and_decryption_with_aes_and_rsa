"""Module providing Cryptography tools and methods."""
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#from Crypto.Util.Padding import pad, unpad
#from moo import ECB_MOO, CBC_MOO, CFB_MOO, OFB_MOO, CTR_MOO

def pad_and_trunc(msg):
    """For padding and truncating plaintext to program's constraints."""
    block_size, num_blocks = 16, 10
    ptext_size = block_size * num_blocks # in bytes
    print("Message chosen is: ", msg)

    if(len(msg) > ptext_size):
        trunc_msg = msg[:ptext_size]
        print("Message is greater than 10 blocks, it will be truncated to: ", trunc_msg)
        return trunc_msg, len(trunc_msg)
    if(len(msg) < ptext_size): # msg ex. 'helloworld' then 10 bytes length < ptext_size of 160
        pad_msg, msg_length = paddington(block_size, num_blocks, msg)
        print("Message is less than 10 blocks, it will be padded to: ", pad_msg)
        return pad_msg, msg_length
    else:
        return msg, ptext_size # when the msg is already exactly 10 blocks long

def paddington(block_size, num_blocks, msg):
    """Method for padding specifically for this implementation."""
    # When the number of bytes in a plaintext is below 160 (block_size multiplied by num_blocks), then subtract that number from 160 to get the number of bytes needed to "pad" until 10 blocks
    # or 160 bytes, add that number of bytes as the padding value per the pkcs7 scheme, using byte strings. if i have 'helloworld' for example, that is 10 bytes, i need 150 bytes to get to the
    # required number of bytes in this implementation, because we are doing a size of 10 blocks across each MOO, but the user should be able to maintain their plaintext, rather than the plaintext
    # becoming 'helloworld' 10 times. so at the end, everything that is not the plaintext should be removed.
    total_bytes = block_size * num_blocks # 160 bytes
    msg_length = len(msg)
    difference_bytes = total_bytes - msg_length
    padding_value = bytes([difference_bytes] * difference_bytes)
    msg_bytes = bytes(msg, 'UTF-8')
    padded_msg = msg_bytes + padding_value
    print(padded_msg)
    return padded_msg, msg_length

def unpaddington(padded_ptext, msg_length):
    """*******! *Unpads your message."""
    padded_ptext = padded_ptext[:msg_length]
    print(padded_ptext)
    return padded_ptext

def mode_analysis(msg, rounds=1):
    """Function for printing results of ModeOfOperation Analysis."""
    processed_msg, msg_length = pad_and_trunc(msg)
    key_random = get_random_bytes(16)
    key_same = b'wedonotcarewedon'
    print("Random key is : ", key_random)
    print("Same key is: ", key_same)

    for round_num in range(1, rounds+1):
        print(f"===Round {round_num}===")
        print("====ECB MODE====")
        cipher_ecb_ran_key = AES.new(key_random, AES.MODE_ECB) # use this as plaintext variable's object.
        cipher_ecb_same_key = AES.new(key_same, AES.MODE_ECB) # use this as plaintext variable's object.

        ciphertext_ecb_ran_key = cipher_ecb_ran_key.encrypt(processed_msg) # use this as .decrypt() method's parameter
        print("Ciphertext of random key:\n", ciphertext_ecb_ran_key)

        ciphertext_ecb_same_key = cipher_ecb_same_key.encrypt(processed_msg) # use this as .decrypt() method's parameter
        print("Ciphertext of same key:\n", ciphertext_ecb_same_key)

        plaintext_ecb_ran_key = unpaddington(cipher_ecb_ran_key.decrypt(ciphertext_ecb_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_ecb_ran_key)

        plaintext_ecb_same_key = unpaddington(cipher_ecb_same_key.decrypt(ciphertext_ecb_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_ecb_same_key)

        print("====CBC MODE====")
        cipher_cbc_ran_key = AES.new(key_random, AES.MODE_CBC) # replace with my moo implementation later
        cipher_cbc_same_key = AES.new(key_same, AES.MODE_CBC)

        ciphertext_cbc_ran_key_bytes = cipher_cbc_ran_key.encrypt(processed_msg)
        print("Ciphertext bytes of random key:\n", ciphertext_cbc_ran_key_bytes)

        ciphertext_cbc_same_key_bytes = cipher_cbc_same_key.encrypt(processed_msg)
        print("Ciphertext bytes of same key:\n", ciphertext_cbc_same_key_bytes)

        iv = b64encode(cipher_cbc_ran_key.iv).decode('utf-8')
        ct_cbc_ran_key = b64encode(ciphertext_cbc_ran_key_bytes).decode('utf-8')
        print("IV:", iv, "Ciphertext of random key:\n", ct_cbc_ran_key)

        iv2 = b64encode(cipher_cbc_same_key.iv).decode('utf-8')
        ct_cbc_same_key = b64encode(ciphertext_cbc_same_key_bytes).decode('utf-8')
        print("IV:", iv2, "Ciphertext of same key:\n", ct_cbc_same_key)

        decipher_cbc_ran_key = AES.new(key_random, AES.MODE_CBC, iv=cipher_cbc_ran_key.iv)
        plaintext_cbc_ran_key = unpaddington(decipher_cbc_ran_key.decrypt(ciphertext_cbc_ran_key_bytes), msg_length)
        print("Decrypted from random key:\n", plaintext_cbc_ran_key)

        decipher_cbc_same_key = AES.new(key_same, AES.MODE_CBC, iv=cipher_cbc_same_key.iv)
        plaintext_cbc_same_key = unpaddington(decipher_cbc_same_key.decrypt(ciphertext_cbc_same_key_bytes), msg_length)
        print("Decrypted from same key:\n", plaintext_cbc_same_key)

        print("====CFB MODE====")
        cipher_cfb_ran_key = AES.new(key_random, AES.MODE_CFB) 
        cipher_cfb_same_key = AES.new(key_same, AES.MODE_CFB)

        ciphertext_cfb_ran_key = cipher_cfb_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_cfb_ran_key)

        ciphertext_cfb_same_key = cipher_cfb_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_cfb_same_key)

        decipher_cfb_ran_key = AES.new(key_random, AES.MODE_CFB, iv=cipher_cfb_ran_key.iv)
        plaintext_cfb_ran_key = unpaddington(decipher_cfb_ran_key.decrypt(ciphertext_cfb_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_cfb_ran_key)

        decipher_cfb_same_key = AES.new(key_same, AES.MODE_CFB, iv=cipher_cfb_same_key.iv)
        plaintext_cfb_same_key = unpaddington(decipher_cfb_same_key.decrypt(ciphertext_cfb_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_cfb_same_key)

        print("====OFB MODE====")
        cipher_ofb_ran_key = AES.new(key_random, AES.MODE_OFB)  
        cipher_ofb_same_key = AES.new(key_same, AES.MODE_OFB)

        ciphertext_ofb_ran_key = cipher_ofb_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_ofb_ran_key)

        ciphertext_ofb_same_key = cipher_ofb_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_ofb_same_key)

        decipher_ofb_ran_key = AES.new(key_random, AES.MODE_OFB, iv=cipher_ofb_ran_key.iv)
        plaintext_ofb_ran_key = unpaddington(decipher_ofb_ran_key.decrypt(ciphertext_ofb_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_ofb_ran_key)

        decipher_ofb_same_key = AES.new(key_same, AES.MODE_OFB, iv=cipher_ofb_same_key.iv)
        plaintext_ofb_same_key = unpaddington(decipher_ofb_same_key.decrypt(ciphertext_ofb_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_ofb_same_key)

        print("====CTR MODE====")
        cipher_ctr_ran_key = AES.new(key_random, AES.MODE_CTR, nonce=b64encode(get_random_bytes(8))) 
        cipher_ctr_same_key = AES.new(key_same, AES.MODE_CTR, nonce=b64encode(get_random_bytes(8)))

        ciphertext_ctr_ran_key = cipher_ctr_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_ctr_ran_key)

        ciphertext_ctr_same_key = cipher_ctr_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_ctr_same_key)

        decipher_ctr_ran_key = AES.new(key_random, AES.MODE_CTR, nonce=cipher_ctr_ran_key.nonce)
        plaintext_ctr_ran_key = unpaddington(decipher_ctr_ran_key.decrypt(ciphertext_ctr_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_ctr_ran_key)

        decipher_ctr_same_key = AES.new(key_same, AES.MODE_CTR, nonce=cipher_ctr_same_key.nonce)
        plaintext_ctr_same_key = unpaddington(decipher_ctr_same_key.decrypt(ciphertext_ctr_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_ctr_same_key)

def encrypt_menu(song_lyrics, deep_quote):
    """Simple terminal menu for users to choose what they want to encrypt and analyze."""
    running = True
    while(running):
        user_input = input("Use provided plaintext [1] or input your own [2], padding and truncation will be performed to 10 blocks if needed.\nINPUT '1' or '2': ")
        match user_input:
            case "1":
                program_provided_plaintext = input("Select song lyrics [1] or quote [2]. ")
                match program_provided_plaintext:
                    case "1":
                        mode_analysis(song_lyrics, 10)
                        running = ask_again(running)
                    case "2":
                        mode_analysis(deep_quote, 10)
                        running = ask_again(running)
                    case _:
                        print("Invalid input.")
                        running = ask_again(running)
            case "2":
                user_provided_plaintext = input("Enter plaintext: ")
                mode_analysis(user_provided_plaintext, 10)
                running = ask_again(running)
            case "exit":
                running = False
            case _:
                print("Invalid input.")

def ask_again(running):
    """Method gives loop functionality rather than having to start stop."""
    ask_user = input("Encrypt more messages with [1], close program with [exit]: ")
    if ask_user == "1":
        return True
    elif ask_user.lower() == "exit":
        return False
    else:
        print("Invalid input.")
        return ask_again(running)

def main():
    """Main method... c'mon pylint this is getting ridiculous."""
    
    song_lyrics = b"""Summertime and the livings easy
And Bradleys on the microphone with Ras M.G.
All the people in the dance will agree
That were well qualified to represent the LBC
Me, and me, and Louie, will young run to the party
Dance to the rhythm it gets harder
(And we can do it like this, in the place to be)

Me and my girl we got this relationship
I love her so bad but she treats me like shit
On lockdown like a penitentiary
She spreads her lovin all over
And when she gets home theres none left for me

Summertime and the livings easy
Bradley's on the microphone with Ras M.G.
All people in the dance will agree
That were well qualified to represent the LBC
Me, me and Louie, we gon run to the party
Dance to the rhythm it gets harder
(And we can do it like this, in the place to be)

Oh take this veil from off my eyes
My burning sun will some day rise
So what am I gonna be doin for a while?
Said Im gonna play with myself
Show them now we've come off the shelf
So what?

Summertime and the livings easy
Bradleys on the microphone with Ras M.G.
All people in the dance will agree
That were well qualified to represent the LBC
Me, me and Louie run to the party
Dance to the rhythm it gets harder
(And we can do it like this, in the place to be)

Evil
Ive come to tell you that shes evil most definitely
Evil
Ornery scandalous and evil most definitely
The tension: it's getting hotter
Id like to hold her head underwater

Me and my girl we got a relationship
Me and my girl we got a relationship
My girl. We got a relationship
oh, and my girl. We got a relationship

Take a tip, take a tip, take a tip, tip, tip from me
Bradleys on the microphone with Ras M.G.
All people in the dance will agree
That we're well qualified to represent the LBC
Me, la la Louie well everybody run to the rhythm it gets harder
(And we can do it like this, in the place to be)

Summertime, the livings easy"""

    deep_quote = b"""As fwies to wanton boys, we awe fow the Gods. 
    They kiww us fow the spowt. 
    Soon the science wiww not onwy be abwe to thwow down the ageing of the cewws,
    the science wiww fix the cewws to the state, and so weww become etewnaw. 
    Onwy accidents, cwimes, waws wiww stiww kiww us. But unfowtunatewy, cwimes and waws wiww muwtipwy. 
    I wove footbaww. Thank you."""

    encrypt_menu(song_lyrics, deep_quote)


if __name__ == "__main__":
    main()
