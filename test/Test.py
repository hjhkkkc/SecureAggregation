import sys
sys.path.append("../")
import Config
import Random
from AE import AE
from Vector import Vector
from KeyAgreement import KeyAgreement
from SecretSharing import SecretSharing
from DigitalSignature import DigitalSignature

def test_SecretSharing():

    # shares = S.share(6, 30, 50)
    t = 30
    u = 50
    secret = 3297529195
    print("secret : ", secret)
    shares = SecretSharing.share(secret, t, u)
    # for i in range(len(shares)):
    #     print("shares {} : ({},{})".format(i, shares[i][0], shares[i][1]))
    m = 10
    offset = 10
    secret = SecretSharing.reconstruction(shares[offset : offset + t + m], t)
    print("secret : ", secret)


def test_DigitalSignature():
    sk, pk = DigitalSignature.gen(1024)
    # m = b"hello world!"
    m = "hello world!"
    # print(sk)
    # print(pk)
    sigma = DigitalSignature.sig(sk, m)
    # print(sigma)
    # sigma = 2323222222222
    print(DigitalSignature.ver(pk, m, sigma))

def test_KeyAgreement():
    A_sk, A_pk = KeyAgreement.gen(Config.pp1024)
    print(A_sk)
    print(A_pk)
    B_sk, B_pk = KeyAgreement.gen(Config.pp1024)
    print(B_sk)
    print(B_pk)
    KA = KeyAgreement.agree(A_sk, B_pk)
    print(KA)
    KB = KeyAgreement.agree(B_sk, A_pk)
    print(KB)
    print(KA == KB)

def test_AE():
    # k = AE.gen(128)
    k = "1234567887654321"
    k = k.encode()
    m = "hello world! " * 100
    print(m)
    c = AE.enc(k, m)
    m = AE.dec(k, c)
    print("dec : ", m)

def test_PRG():
    s = 124893949857399857398459754934858973598359
    # s = None
    print(Random.PRG(s, Config.Ru, Config.m))

def test_vector():
    a = Vector(Random.PRG(None, Config.Ru, Config.m))
    print("a : ", a)
    b = Vector(Random.PRG(None, Config.Ru, Config.m))
    print("b : ", b)
    c = a + b 
    print("a + b : ", c)
    c = a - b 
    print("a - b : ", c)
    c = a * 3
    print("a * 3 : ", c)
    l = [a, b]
    print(l)
    print(str(l))

def main():
    test_SecretSharing()
    # test_DigitalSignature()
    # test_KeyAgreement()
    # test_AE()
    # test_PRG()
    # test_vector()

if __name__ == "__main__":
    main()
