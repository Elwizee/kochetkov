"""Задача 20: Гомоморфное шифрование (примитив)."""


def encrypt_number(num: int, key: int, p: int) -> int:
    return (num * key) % p


def decrypt_number(cipher: int, key: int, p: int) -> int:
    key_inv = pow(key, -1, p)
    return (cipher * key_inv) % p


def homomorphic_multiply(c1: int, c2: int, key: int, p: int) -> tuple[int, int]:
    """
    Для шифра Enc(x) = x * key mod p:
    Enc(a) * Enc(b) * key^(-1) mod p = Enc(a * b)
    """
    key_inv = pow(key, -1, p)
    product_cipher = (c1 * c2 * key_inv) % p
    a = decrypt_number(c1, key, p)
    b = decrypt_number(c2, key, p)
    expected = encrypt_number(a * b, key, p)
    return product_cipher, expected


if __name__ == "__main__":
    p = 104729
    key = 42
    a, b = 7, 13

    enc_a = encrypt_number(a, key, p)
    enc_b = encrypt_number(b, key, p)
    product, expected = homomorphic_multiply(enc_a, enc_b, key, p)

    print(f"a = {a}, b = {b}")
    print(f"Enc(a) = {enc_a}, Enc(b) = {enc_b}")
    print(f"Enc(a) * Enc(b) * key^(-1) mod p = {product}")
    print(f"Enc(a * b) = {expected}")
    print(f"Гомоморфность: {product == expected}")
    print(f"Dec(результат) = {decrypt_number(product, key, p)} (ожидалось {a * b})")
