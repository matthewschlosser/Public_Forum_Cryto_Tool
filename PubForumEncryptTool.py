from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from os.path import getsize, isfile
import sys

# buffer blocks of bytes from a file in chunks (for
# efficient I/O)
def blocks_from_file(filename, chunksize=8192, blocksize=16):
  try:
    with open(filename, 'rb') as f:
      chunk = f.read(chunksize)
      while chunk:
        chunk = chunk.ljust((len(chunk)//blocksize + 1) * 16, b'\0') # right pad to block size with null byte
        for i in range(0, len(chunk), blocksize):
          yield chunk[i:i+blocksize]
        chunk = f.read(chunksize)
  except FileNotFoundError:
    print('File not found: {}'.format(filename))


# perform first time setup by generating public/private key
# pair for sharing file symmetric keys
def setupKeyPairs():
  rsa = RSA.generate(4096)
  pubkey = rsa.publickey().exportKey('PEM')
  privkey = rsa.exportKey('PEM')
  with open('privkey.pem','wb') as f:
    f.write(privkey)
  with open('pubkey.pem','wb') as f:
    f.write(privkey)

# encrypt file with AES-256, then encrypt the key with each
# public key in pub_keys, appending the encrypted key to the
# output file
def produceEncrypted(filename, pub_keys):
  filekey = Random.new().read(32) # AES-256 key
  h = SHA.new(filekey).digest() # hash the file key
  encfn = encryptFile(filename, filekey)
  for pbkey_name in pub_keys:
    try:
      with open(pbkey_name, 'rb') as pbkey,\
           open('KEY-{}_{}'.format(filename, pbkey_name), 'wb') as enc_key:
        pk = RSA.importKey(pbkey.read())
        cipher = PKCS1_v1_5.new(pk)
        enc_key.write(cipher.encrypt(filekey+h))
    except FileNotFoundError:
      print('public key file not found: {}'.format(pbkey_name))
  return encfn

# write iv and encrypted file contents to new file
def encryptFile(filename, key):
  iv = Random.new().read(AES.block_size) # generate IV
  c = AES.new(key, AES.MODE_CBC, iv) # new CBC AES cipher
  encfilename = 'ENC-{}'.format(filename)
  with open(encfilename, 'wb') as f:
    f.write(iv) # first bytes are IV
    for block in blocks_from_file(filename): # rest are encrypted file
      f.write(c.encrypt(block))
  return encfilename

# using encrypted file and encrypted key file, get decrypted file
def decryptFromEncryptedKey(encfilename, keyfilename, privkey):
  privkey = RSA.importKey(open(privkey).read()) # get own private key
  filesize = getsize(encfilename) - AES.block_size # get encrypted file size
  sentinel = Random.new().read(filesize + SHA.digest_size) # make sentinel
  cipher = PKCS1_v1_5.new(privkey) # make new RSA cipher object w/own private key
  with open(keyfilename, 'rb') as keyfile:
    decrypted = cipher.decrypt(keyfile.read(), sentinel) # decrypt key file
    dec_filekey = decrypted[:-SHA.digest_size] # parse file key
    dec_digest = SHA.new(dec_filekey).digest() # compute hash of decrypted
    if dec_digest != decrypted[-SHA.digest_size:]: # decryption failure
      return -1
  iv = None
  c = None
  decfn = 'DEC-{}'.format(encfilename[4:])
  with open(decfn,'wb') as decfile:
    for block in blocks_from_file(encfilename):
      if iv is None: # first block is IV
        iv = block
        c = AES.new(dec_filekey, AES.MODE_CBC, iv)
        continue
      decfile.write(c.decrypt(block.rstrip(b'\0')))
  return decfn

if __name__ == "__main__":
  if len(sys.argv) == 1:
    print("Available options: setup, encrypt, decrypt")
  elif len(sys.argv) > 2:
    print('Too many arguments')
  elif sys.argv[1] == "setup":
    confirm = 'y'
    if isfile('pubkey.pem') or isfile('privkey.pem'):
      confirm = None
      while confirm != "y" and confirm != "n":
        confirm = input("There are key files that may be overwritten. Continue? (y/n): ").lower().strip()
    if confirm == "y":
      setupKeyPairs()
      print("Setup complete")
  elif sys.argv[1] == 'encrypt':
    filename = input('Enter name of file to encrypt: ')
    pubkeys = input('Enter name of public key files, separated by commas: ')
    pubkeys = [ i.strip() for i in pubkeys.split(',')]
    encfn = produceEncrypted(filename, pubkeys)
    print('Encrypted file saved to {}'.format(encfn))
  elif sys.argv[1] == 'decrypt':
    filename = input('Enter name of file to decrypt: ')
    keyfile = input('Enter name of encrypted key file: ')
    privkey = input('Enter name of private key file: ')
    decfn = decryptFromEncryptedKey(filename, keyfile, privkey)
    print('Decrypted file saved to {}'.format(decfn))
  else:
    print('Unknown argument')
