"""Module providing Cryptography tools and methods."""
import random, time
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
#from Crypto.Util.Padding import pad, unpad
from moo import CbcMoo, CfbMoo, OfbMoo, CtrMoo

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

def introduce_error(ciphertext):
    """Bit flip method."""
    if len(ciphertext) > 0:
        position_to_flip = random.randint(0, len(ciphertext) - 1)
        bit_to_flip = 1 << random.randint(0, 7)
        modified_byte = ciphertext[position_to_flip] ^ bit_to_flip
        
        modified_ciphertext = ciphertext[:position_to_flip] + bytes([modified_byte]) + ciphertext[position_to_flip + 1:]
        return modified_ciphertext
    else:
        return ciphertext

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

        print("====ERRORS IN ECB====")
        original_ciphertext_ran_key = cipher_ecb_ran_key.encrypt(processed_msg)
        alt_ciphertext_ran_key = introduce_error(original_ciphertext_ran_key)

        original_ciphertext_same_key = cipher_ecb_same_key.encrypt(processed_msg)
        alt_ciphertext_same_key = introduce_error(original_ciphertext_same_key)
        print("Error propagated random key:", alt_ciphertext_ran_key)
        print("Error propagated same key:", alt_ciphertext_same_key)

        decrypt_attempt_ecb_ran_key = unpaddington(cipher_ecb_ran_key.decrypt(alt_ciphertext_ran_key), msg_length)
        decrypt_attempt_ecb_same_key = unpaddington(cipher_ecb_same_key.decrypt(alt_ciphertext_same_key), msg_length)

        print("Decrypt attempt from error propagated random key:", decrypt_attempt_ecb_ran_key)
        print("Decrypt attempt from error propagated same key:", decrypt_attempt_ecb_same_key)

        print("====CBC MODE====")
        cipher_cbc_ran_key = CbcMoo(key_random) # replace with my moo implementation later
        cipher_cbc_same_key = CbcMoo(key_same)

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

        plaintext_cbc_ran_key = unpaddington(cipher_cbc_ran_key.decrypt(ciphertext_cbc_ran_key_bytes), msg_length)
        print("Decrypted from random key:\n", plaintext_cbc_ran_key)

        plaintext_cbc_same_key = unpaddington(cipher_cbc_same_key.decrypt(ciphertext_cbc_same_key_bytes), msg_length)
        print("Decrypted from same key:\n", plaintext_cbc_same_key)

        print("====ERRORS IN CBC====")
        original_ciphertext_ran_key_cbc = cipher_cbc_ran_key.encrypt(processed_msg)
        alt_ciphertext_ran_key_cbc = introduce_error(original_ciphertext_ran_key_cbc)

        original_ciphertext_same_key_cbc = cipher_cbc_same_key.encrypt(processed_msg)
        alt_ciphertext_same_key_cbc = introduce_error(original_ciphertext_same_key_cbc)

        print("Error propagated:", alt_ciphertext_ran_key_cbc)
        print("Error propagated:", alt_ciphertext_same_key_cbc)

        decrypt_attempt_cbc_ran_key = unpaddington(cipher_cbc_ran_key.decrypt(alt_ciphertext_ran_key_cbc), msg_length)
        decrypt_attempt_cbc_same_key = unpaddington(cipher_cbc_same_key.decrypt(alt_ciphertext_same_key_cbc), msg_length)

        print("Decrypt attempt from error propagated random key:", decrypt_attempt_cbc_ran_key)
        print("Decrypt attempt from error propagated same key:", decrypt_attempt_cbc_same_key)

        print("====CFB MODE====")
        cipher_cfb_ran_key = CfbMoo(key_random) 
        cipher_cfb_same_key = CfbMoo(key_same)

        ciphertext_cfb_ran_key = cipher_cfb_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_cfb_ran_key)

        ciphertext_cfb_same_key = cipher_cfb_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_cfb_same_key)

        plaintext_cfb_ran_key = unpaddington(cipher_cfb_ran_key.decrypt(ciphertext_cfb_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_cfb_ran_key)

        plaintext_cfb_same_key = unpaddington(cipher_cfb_same_key.decrypt(ciphertext_cfb_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_cfb_same_key)

        print("====ERRORS IN CFB====")
        original_ciphertext_ran_key_cfb = cipher_cfb_ran_key.encrypt(processed_msg)
        alt_ciphertext_ran_key_cfb = introduce_error(original_ciphertext_ran_key_cfb)

        original_ciphertext_same_key_cfb = cipher_cfb_same_key.encrypt(processed_msg)
        alt_ciphertext_same_key_cfb = introduce_error(original_ciphertext_same_key_cfb)

        print("Error propagated:", alt_ciphertext_ran_key_cfb)
        print("Error propagated:", alt_ciphertext_same_key_cfb)

        decrypt_attempt_cfb_ran_key = unpaddington(cipher_cfb_ran_key.decrypt(alt_ciphertext_ran_key_cfb), msg_length)
        decrypt_attempt_cfb_same_key = unpaddington(cipher_cfb_same_key.decrypt(alt_ciphertext_same_key_cfb), msg_length)

        print("Decrypt attempt from error propagated random key:", decrypt_attempt_cfb_ran_key)
        print("Decrypt attempt from error propagated same key:", decrypt_attempt_cfb_same_key)

        print("====OFB MODE====")
        cipher_ofb_ran_key = OfbMoo(key_random)
        cipher_ofb_same_key = OfbMoo(key_same)

        ciphertext_ofb_ran_key = cipher_ofb_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_ofb_ran_key)

        ciphertext_ofb_same_key = cipher_ofb_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_ofb_same_key)

        plaintext_ofb_ran_key = unpaddington(cipher_ofb_ran_key.decrypt(ciphertext_ofb_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_ofb_ran_key)

        plaintext_ofb_same_key = unpaddington(cipher_ofb_same_key.decrypt(ciphertext_ofb_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_ofb_same_key)

        print("====ERRORS IN OFB====")
        original_ciphertext_ran_key_ofb = cipher_ofb_ran_key.encrypt(processed_msg)
        alt_ciphertext_ran_key_ofb = introduce_error(original_ciphertext_ran_key_ofb)

        original_ciphertext_same_key_ofb = cipher_ofb_same_key.encrypt(processed_msg)
        alt_ciphertext_same_key_ofb = introduce_error(original_ciphertext_same_key_ofb)

        print("Error propagated:", alt_ciphertext_ran_key_ofb)
        print("Error propagated:", alt_ciphertext_same_key_ofb)

        decrypt_attempt_ofb_ran_key = unpaddington(cipher_ofb_ran_key.decrypt(alt_ciphertext_ran_key_ofb), msg_length)
        decrypt_attempt_ofb_same_key = unpaddington(cipher_ofb_same_key.decrypt(alt_ciphertext_same_key_ofb), msg_length)

        print("Decrypt attempt from error propagated random key:", decrypt_attempt_ofb_ran_key)
        print("Decrypt attempt from error propagated same key:", decrypt_attempt_ofb_same_key)

        print("====CTR MODE====")
        cipher_ctr_ran_key = CtrMoo(key_random, nonce=b64encode(get_random_bytes(8))) 
        cipher_ctr_same_key = CtrMoo(key_same, nonce=b64encode(get_random_bytes(8)))

        ciphertext_ctr_ran_key = cipher_ctr_ran_key.encrypt(processed_msg)
        print("Ciphertext of random key:\n", ciphertext_ctr_ran_key)

        ciphertext_ctr_same_key = cipher_ctr_same_key.encrypt(processed_msg)
        print("Ciphertext of same key:\n", ciphertext_ctr_same_key)

        plaintext_ctr_ran_key = unpaddington(cipher_ctr_ran_key.decrypt(ciphertext_ctr_ran_key), msg_length)
        print("Decrypted from random key:\n", plaintext_ctr_ran_key)

        plaintext_ctr_same_key = unpaddington(cipher_ctr_same_key.decrypt(ciphertext_ctr_same_key), msg_length)
        print("Decrypted from same key:\n", plaintext_ctr_same_key)

        print("====ERRORS IN CTR====")
        original_ciphertext_ran_key_ctr = cipher_ctr_ran_key.encrypt(processed_msg)
        alt_ciphertext_ran_key_ctr = introduce_error(original_ciphertext_ran_key_ctr)

        original_ciphertext_same_key_ctr = cipher_ctr_same_key.encrypt(processed_msg)
        alt_ciphertext_same_key_ctr = introduce_error(original_ciphertext_same_key_ctr)

        print("Error propagated random key:", alt_ciphertext_ran_key_ctr)
        print("Error propagated same key:", alt_ciphertext_same_key_ctr)

        decrypt_attempt_ctr_ran_key = unpaddington(cipher_ctr_ran_key.decrypt(alt_ciphertext_ran_key_ctr), msg_length)
        decrypt_attempt_ctr_same_key = unpaddington(cipher_ctr_same_key.decrypt(alt_ciphertext_same_key_ctr), msg_length)
        
        print("Decrypt attempt from error propagated random key:", decrypt_attempt_ctr_ran_key)
        print("Decrypt attempt from error propagated random key:", decrypt_attempt_ctr_same_key)

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

def measure_time(func, *args):
    start_time = time.time()
    result = func(*args)
    elapsed_time = time.time() - start_time
    return result, elapsed_time

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

    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                                protection="scryptAndAES128-CBC")

    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)
    file_out.close()

    print(key.publickey().export_key())

    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)

    print(key.publickey().export_key())

    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(song_lyrics)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()
    
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    file_in.close()

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))

if __name__ == "__main__":
    main()
