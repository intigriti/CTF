from pwn import *
from Crypto.Util.number import *
import re
from sympy import isprime, factorint


class Card:
    VALUE_TO_NAME = {
        1: "Ace",
        11: "Jack",
        12: "Queen",
        13: "King",
    }

    NAME_TO_VALUE = {
        "Ace": 1,
        "Jack": 11,
        "Queen": 12,
        "King": 13,
    }

    def __init__(self, suit, value):
        self.suit = suit
        self.value = value

    def __repr__(self):
        name = self.VALUE_TO_NAME.get(self.value, str(self.value))
        return f"{name} of {self.suit}"

    @staticmethod
    def repr_to_card(repr):
        value, suit = repr.split(" of ")
        if value in Card.NAME_TO_VALUE:
            value = Card.NAME_TO_VALUE.get(value)
        else:
            value = int(value)
        return Card(suit, value)


class Deck:
    def __init__(self):
        self.reset()

    def reset(self):
        self.cards = []
        self.build()

    def build(self):
        for suit in ["Hearts", "Diamonds", "Clubs", "Spades"]:
            for value in range(1, 14):
                self.cards.append(Card(suit, value))

    def get_card_index(self, card):
        for i, c in enumerate(self.cards):
            if c.suit == card.suit and c.value == card.value:
                return i


def get_initial_cards():
    rem.recvuntil(b"Dealer")
    dealer_card = Card.repr_to_card(
        rem.recvline_startswith(b"- ").decode()[2:])
    rem.recvline()
    cards = [dealer_card, None]
    for _ in range(2 * 8):
        card = Card.repr_to_card(rem.recvline_startswith(b"- ").decode()[2:])
        cards.append(card)
    return cards


def pred_next_step(all_bytes):
    return all_bytes.endswith(b"-\n") or all_bytes.endswith(b"stand? ")


def get_hits(res):
    return ["".join(c) for c in re.findall("((?<=hits )[a-zA-Z0-9]+ of [a-zA-Z]+)|((?<=hit )[a-zA-Z0-9]+ of [a-zA-Z]+)", res.decode(errors="surrogateescape"))]


def cards_to_seed(cards):
    card_indices = []
    deck = Deck()
    for i, card in enumerate(cards):
        card_index = deck.get_card_index(card)
        deck.cards.pop(card_index)
        if len(deck.cards) == 0:
            deck.reset()
        card_indices.append((card_index, i % 52))
    assert card_indices[-1][0] == 0, "Not enough info to fully recover seed"
    seed = 0
    for card_index, i in card_indices[::-1]:
        seed *= 52 - i
        seed += card_index
    return seed


def encrypt(data):
    global rem
    rem = remote("localhost", "1337")
    rem.sendlineafter(b"name? ", data)
    flag_enc = bytes_to_long(bytes.fromhex(
        rem.recvline_contains(b"is: ").decode().split(": ")[1]))

    cards = get_initial_cards()

    num = 1
    while True:
        res = rem.recvpred(pred_next_step)
        if res == b"":
            break
        if b"Hit or stand?" in res:
            rem.sendline(b"hit")
        if b"Game over!" in res:
            new_cards = [Card.repr_to_card(c) for c in get_hits(res)]
            cards.extend(new_cards)
            dealer_cards = re.findall(
                "[a-zA-Z0-9]+ of [a-zA-Z]+", res.decode())
            dealer_cards = [Card.repr_to_card(c) for c in dealer_cards]
            hidden_index = cards.index(None)
            cards[hidden_index] = dealer_cards[1]
            if num != 3:
                cards.extend(get_initial_cards())
            num += 1
            continue
        new_cards = [Card.repr_to_card(c) for c in get_hits(res)]
        cards.extend(new_cards)
    rem.close()
    return (flag_enc, cards_to_seed(cards))


_, secret = encrypt(b"\x01")
assert long_to_bytes(secret) == b"Security through obscurity"

N_BITS = 350
data = long_to_bytes(2 ** (N_BITS - secret.bit_length() + 1))
flag_enc, data_enc = encrypt(data)
n_multiple = bytes_to_long(data) * secret - data_enc
n = max(factorint(n_multiple).keys())
assert isprime(n)
assert n.bit_length() == N_BITS

secret_inv = pow(secret, -1, n)
flag = long_to_bytes((flag_enc * secret_inv) % n)
print(flag.decode())
