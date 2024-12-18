use std::str::FromStr;

use cantor_zassenhaus::{
    distinct_degree_factorize, factor, square_free_factorization, F128Element, F128Polynomial,
};

pub mod cantor_zassenhaus;
pub mod cli;

pub const MINI_HEADER_SIZE: usize = 20;
pub const TAG_SIZE: usize = 16;

pub fn split_ciphertext(ad: &[u8], ct: &[u8]) -> Vec<[u8; 16]> {
    let mut blocks = ad
        .chunks(16)
        .chain(ct.chunks(16))
        .map(|x| {
            let mut block = x.to_vec();
            block.extend_from_slice(vec![0; 16 - x.len()].as_slice());
            block.try_into().unwrap()
        })
        .collect::<Vec<_>>();

    let mut length_block = (ad.len() * 8).to_be_bytes().to_vec();
    length_block.extend_from_slice(&(ct.len() * 8).to_be_bytes());

    blocks.push(length_block.as_slice().try_into().unwrap());

    blocks
}

pub fn ghash(ad: &[u8], ct: &[u8], h: [u8; 16]) -> F128Element {
    let h = F128Element::from_block(h);
    let blocks = split_ciphertext(ad, ct);
    let blocks = blocks.into_iter().map(F128Element::from_block);
    let mut res = F128Element(0);
    for block in blocks {
        res = res + block;
        res = res * h;
    }
    res
}

#[derive(Clone, Debug)]
pub struct Message {
    pub tag: [u8; TAG_SIZE],
    pub associated_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub blocks: Vec<[u8; 16]>,
}
impl FromStr for Message {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, message) = s.split_once(':').ok_or("Failed to split message")?;
        let header = hex::decode(prefix).map_err(|_| "Failed to hex decode header")?;
        let ciphertext = hex::decode(message).map_err(|_| "Failed to hex decode ciphertext")?;

        let (mini_header, tag) = header.split_at(MINI_HEADER_SIZE);
        let tag = tag.try_into().map_err(|_| "Failed to parse tag")?;
        let blocks = split_ciphertext(mini_header, &ciphertext);

        Ok(Message {
            tag,
            associated_data: mini_header.to_vec(),
            ciphertext,
            blocks,
        })
    }
}

#[derive(Debug)]
pub struct Solver {
    pub messages: [Message; 3],
}

impl Solver {
    pub fn new(messages: [&str; 3]) -> Solver {
        let messages = [
            messages[0].parse().unwrap(),
            messages[1].parse().unwrap(),
            messages[2].parse().unwrap(),
        ];

        Solver { messages }
    }

    pub fn solve(&self) -> Result<Solved, String> {
        let [m1, m2, m3] = self.messages.clone();

        let mut coefs = vec![];
        for (block1, block2) in m1.blocks.into_iter().zip(m2.blocks.into_iter()) {
            coefs.push(F128Element::from_block(block1) + F128Element::from_block(block2));
        }
        coefs.push(F128Element::from_block(m1.tag) + F128Element::from_block(m2.tag));
        coefs.reverse();

        let poly = F128Polynomial::new(coefs);

        let square_free = square_free_factorization(&poly);
        let distinct_degree_factors = distinct_degree_factorize(&square_free);

        let poly = distinct_degree_factors.first().unwrap().0.clone();

        let factors = factor(&poly);
        let zeros = factors
            .iter()
            .map(|x| x.to_monic())
            .flat_map(|x| x.0.first().cloned())
            .collect::<Vec<_>>();

        let (h, y0) = zeros
            .into_iter()
            .find_map(|h| {
                let first = ghash(&m1.associated_data, &m1.ciphertext, h.to_block());
                let y0 = F128Element::from_block(m1.tag) + first;
                let third = ghash(&m3.associated_data, &m3.ciphertext, h.to_block());
                let t3 = third + y0;
                (t3.to_block() == m3.tag).then_some((h, y0))
            })
            .ok_or("Failed to find h and y0")?;

        let nonce = m1.associated_data[..12].try_into().unwrap();

        Ok(Solved { nonce, h, y0 })
    }
}

pub struct Solved {
    nonce: [u8; 12],
    h: F128Element,
    y0: F128Element,
}
impl Solved {
    pub fn create_mini_header(&self, ciphertext: &[u8]) -> [u8; MINI_HEADER_SIZE] {
        let mut mini_header = self.nonce.to_vec();
        mini_header.extend_from_slice(&ciphertext.len().to_be_bytes());
        mini_header.try_into().unwrap()
    }

    pub fn create_tag(&self, mini_header: &[u8], ciphertext: &[u8]) -> [u8; TAG_SIZE] {
        let tag = ghash(mini_header, ciphertext, self.h.to_block()) + self.y0;
        tag.to_block()
    }

    pub fn forge_message(&self, ciphertext: &[u8]) -> String {
        let mini_header = self.create_mini_header(ciphertext);
        let tag = self.create_tag(&mini_header, ciphertext);

        format!(
            "{}{}:{}",
            hex::encode(mini_header),
            hex::encode(tag),
            hex::encode(ciphertext)
        )
    }
}
