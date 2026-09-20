"""Ed25519 and SHA-512 in pure Python. Test material, not something to sign with.

    This exists so the module's signing path has a test. It is not a signer for a
    device and must not become one.

`point_mul` below is the textbook double-and-add: it branches on the bits of the
secret scalar. On anything an attacker can time or measure power on, that hands
over the private key, and there is no way to write constant-time code in
MicroPython -- no control over branching, allocation, or when the collector runs,
and the pauses leak by themselves. A real board signs with the platform's
implementation: `espressif/libsodium` under ESP-IDF, or a native `.mpy` wrapping
something reviewed.

SHA-512 is here because MicroPython's `hashlib` stops at sha256 and Ed25519 needs
it. Its constants were computed and checked against CPython's `hashlib` when this
file was written. SHA-512 has no secret-dependent branches, so that half is only
slow, not dangerous.

Measured 21 September 2026, one signature of the ninety-four bytes aamio signs:
CPython 7 ms, MicroPython 1.25.0 on the same desktop 21 ms, and 1.9 MB of
allocation churn per signature -- which on a board with a few hundred kilobytes is
twenty-odd collections for one signature.
"""

K = [4794697086780616226, 8158064640168781261, 13096744586834688815, 16840607885511220156, 4131703408338449720, 6480981068601479193, 10538285296894168987, 12329834152419229976, 15566598209576043074, 1334009975649890238, 2608012711638119052, 6128411473006802146, 8268148722764581231, 9286055187155687089, 11230858885718282805, 13951009754708518548, 16472876342353939154, 17275323862435702243, 1135362057144423861, 2597628984639134821, 3308224258029322869, 5365058923640841347, 6679025012923562964, 8573033837759648693, 10970295158949994411, 12119686244451234320, 12683024718118986047, 13788192230050041572, 14330467153632333762, 15395433587784984357, 489312712824947311, 1452737877330783856, 2861767655752347644, 3322285676063803686, 5560940570517711597, 5996557281743188959, 7280758554555802590, 8532644243296465576, 9350256976987008742, 10552545826968843579, 11727347734174303076, 12113106623233404929, 14000437183269869457, 14369950271660146224, 15101387698204529176, 15463397548674623760, 17586052441742319658, 1182934255886127544, 1847814050463011016, 2177327727835720531, 2830643537854262169, 3796741975233480872, 4115178125766777443, 5681478168544905931, 6601373596472566643, 7507060721942968483, 8399075790359081724, 8693463985226723168, 9568029438360202098, 10144078919501101548, 10430055236837252648, 11840083180663258601, 13761210420658862357, 14299343276471374635, 14566680578165727644, 15097957966210449927, 16922976911328602910, 17689382322260857208, 500013540394364858, 748580250866718886, 1242879168328830382, 1977374033974150939, 2944078676154940804, 3659926193048069267, 4368137639120453308, 4836135668995329356, 5532061633213252278, 6448918945643986474, 6902733635092675308, 7801388544844847127]

H = [7640891576956012808, 13503953896175478587, 4354685564936845355, 11912009170470909681, 5840696475078001361, 11170449401992604703, 2270897969802886507, 6620516959819538809]

M = (1 << 64) - 1


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M


def sha512(data):
    h = list(H)
    data = bytearray(data)
    length = len(data) * 8
    data.append(0x80)

    while len(data) % 128 != 112:
        data.append(0)

    data += length.to_bytes(16, "big")

    for at in range(0, len(data), 128):
        block = data[at:at + 128]
        w = [int.from_bytes(block[i * 8:i * 8 + 8], "big") for i in range(16)]

        for i in range(16, 80):
            s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)

        a, b, c, d, e, f, g, hh = h

        for i in range(80):
            S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
            ch = (e & f) ^ (~e & M & g)
            t1 = (hh + S1 + ch + K[i] + w[i]) & M
            S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & M
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M

        h = [(x + y) & M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

    return b"".join(x.to_bytes(8, "big") for x in h)


P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def modp_inv(x):
    return pow(x, P - 2, P)


D = -121665 * modp_inv(121666) % P
MODP_SQRT_M1 = pow(2, (P - 1) // 4, P)


def point_add(a, b):
    A, B = (a[1] - a[0]) * (b[1] - b[0]) % P, (a[1] + a[0]) * (b[1] + b[0]) % P
    C, DD = 2 * a[3] * b[3] * D % P, 2 * a[2] * b[2] % P
    E, F, G, H = B - A, DD - C, DD + C, B + A

    return (E * F % P, G * H % P, F * G % P, E * H % P)


def recover_x(y, sign):
    if y >= P:
        return None

    x2 = (y * y - 1) * modp_inv(D * y * y + 1)

    if x2 == 0:
        return None if sign else 0

    x = pow(x2, (P + 3) // 8, P)

    if (x * x - x2) % P != 0:
        x = x * MODP_SQRT_M1 % P

    if (x * x - x2) % P != 0:
        return None

    if (x & 1) != sign:
        x = P - x

    return x


G_Y = 4 * modp_inv(5) % P
G_X = recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % P)


def point_mul(s, point):
    out = (0, 1, 1, 0)

    while s > 0:
        if s & 1:
            out = point_add(out, point)

        point = point_add(point, point)
        s >>= 1

    return out


def point_compress(point):
    zinv = modp_inv(point[2])
    x = point[0] * zinv % P
    y = point[1] * zinv % P

    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def sha512_int(data):
    return int.from_bytes(sha512(data), "little")


def secret_expand(secret):
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)

    return a, h[32:]


def sign(secret, message):
    a, prefix = secret_expand(secret)
    public = point_compress(point_mul(a, G))
    r = sha512_int(prefix + message) % Q
    big_r = point_compress(point_mul(r, G))
    h = sha512_int(big_r + public + message) % Q

    return big_r + int.to_bytes((r + h * a) % Q, 32, "little")


