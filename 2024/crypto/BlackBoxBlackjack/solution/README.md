The puzzle is a game of blackjack consisting of the dealer and 8 other players, one of whom is you.
The majority of the blackjack logic isn't important. The key points are:

-   The deck shuffling uses a seed based on your name
-   The shuffling is insecure and can be reversed to work out the seed
-   The seed is the encryption of your name, with the cryptosystem redacted, making it a _black box_

The flag is the dealer's name, which you have to decrypt.
From observation, the encrypted flag is different for each session.
There is a `n_bits=350` property being passed to the cryptosystem,
and `getPrime` is imported but unused in the redacted challenge code.
It's safe to assume there is some kind of random prime generation going on,
although knowing this is not necessary for the puzzle.

The deck shuffling algorithm:

```py
def shuffle(self):
    new_cards = []
    for i in range(52):
        card_index = self.seed % (52 - i)
        new_cards.append(self.cards.pop(card_index))
        self.seed //= (52 - i)
    self.cards = new_cards
```

With 9 players including the dealer, and 3 games, there are 54 known cards.
There are several more as a result of players hitting and gaining more cards.
The exact number depends on how the game pans out, but it's roughly between 80-90.

If `seed` reaches 0 (or is 0 from the start) then `card_index` will be 0 for the remaining game(s).
The key point is that if we have all of the cards produced by a seed until it reaches 0,
we can reverse this to get the seed.
However, if the seed is so massive that it produces several hundred cards, then we can only gain
partial knowledge about the seed.

The first step is playing through the three games, and recording the cards dealt
in order for a given name. Essentially, a lot of pwntools manipulation. You could also
do this manually if you really wanted to.

For more useful information, convert the cards obtained into the card indices.
Refer to the `cards_to_seed` function in the solve script for this logic.

Let's experiment with some names:  
`"blank"` seems to be pretty random at the start but then a lot of consecutives start showing up (`card_index=0`)  
`"blankblankblankblank"` is mostly random but at the very end it has a lot of `card_index=0`  
`"blank" * 100` exhibits a similar pattern as the previous. Seems like increasing the length of the name increases the number of `card_index=0` but only up to a point

Observe that when `"blank"` is used, the cards are exactly the same every time,
but with longer names they change each session. Perhaps the seed is under some random modulus?
This is important as it shows that the encryption of small names over the reals is smaller than
the modulus, indicating either poor or no padding.

Let's try using the name `b"\x00"`.

All of the cards are consecutive, showing that `E(0) = 0`, bingo.

This could possibly be an RSA-based cryptosystem which exhibits the same property.

Recap on RSA:  
Generate two primes, `p` and `q`  
The modulus, `n = p * q`  
Pick an exponent `e`, usually `3` or `65537`  
`E(x) = x^e (mod n)`  
`E(0) = 0^e = 0`

One important property of RSA is that it is multiplicatively homomorphic.  
In other words, `E(a * b) = E(a) * E(b)`  
This is because `E(a * b) = (a * b)^e = a^e * b^e = E(a) * E(b)`

To see if this property holds for the black box cryptosystem, we first need a way
to get the seed from the cards. As mentioned before, we can capture the full seed
assuming the we have all the cards up to the point that `seed=0`. This is almost
always true, unless you are using a big name and get unlucky with the modulus.
Refer to `cards_to_seed` in the solve script for a reversal of the `shuffle` function.

Now we essentially have an encryption oracle. We can feed arbitrary data and see
what it looks like encrypted. We already know that `E(0) = 0`.

Let's see if this cryptosystem is multiplicatively homomorphic.  
`E(6) != E(3) * E(2)`  
Therefore, it is not.

So it is at the very least not RSA, or at least not in its traditional form.

Let's test for another property, is it additively homomorphic?  
In other words, `E(a + b) = E(a) + E(b)`  
It is!  
Observe that for massive `a` or `b`, this property seems to not hold true.  
This is likely because the property holds over _modulo_, where the modulus is
not known to us.

The simplest form of encryption with this property is `E(x) = c * x` where `c`
is some constant. If this is our cryptosystem, then `E(x != 1) = E(1) * x` should hold.

It does! Essentially, `E(1) = c`. Since `E(x)` where x is small is constant, then `c` must
also be constant. Upon converting the constant value to bytes in big endian form, you get
`b"Security through obscurity"`, proving that we're making some progress.

A simple form of decryption would be `D(x) = x / c`, which works for small plaintexts.

However, when plaintexts get bigger, such as in the case of the flag, it's not so simple
as the encryption is performed `mod n`. We can't confirm how exactly `n` is being
generated, but it's safe to assume that some form of random modulo is present.

`n_bits=350` implies that the modulo `n` is 350-bits. This makes sense as from observation
you can prove that the seed is at most 350-bits.

If we can find a name `x` such that `c * x = E(x) + k * n` where `k` is small, we can calculate
`k * n = c * x - E(x)` and then work out possible `n` values by bruteforcing `k`.

One way to choose `x` is `2^(350 - c.bit_length() + 1)`. This will almost always result in `k = 1`.

From this, we can see that `n` is always a 350-bit prime number. If you knew that `n` was prime to
begin with, then you could factorise `k * n` and pick the biggest prime.

From there, you can calculate the modular inverse of `c`, the secret value, and get the flag!

Here is the unredacted cryptosystem:

```py
class Crypto:
    def __init__(self, n_bits):
        self.n = getPrime(n_bits)
        self.secret = bytes_to_long(b"Security through obscurity")

    def encrypt(self, data):
        return long_to_bytes(self.secret * bytes_to_long(data) % self.n)
```

_Obscurity is not security_
