use solver::{
    cantor_zassenhaus::{
        distinct_degree_factorize, factor, square_free_factorization, F128Element, F128Polynomial,
    },
    ghash, Message, MINI_HEADER_SIZE, TAG_SIZE,
};

fn create_mini_header(nonce: [u8; 12], ciphertext: &[u8]) -> [u8; MINI_HEADER_SIZE] {
    let mut mini_header = nonce.to_vec();
    mini_header.extend_from_slice(&ciphertext.len().to_be_bytes());
    mini_header.try_into().unwrap()
}

fn create_tag(
    h: F128Element,
    y0: F128Element,
    mini_header: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_SIZE] {
    let tag = ghash(mini_header, ciphertext, h.to_block()) + y0;
    tag.to_block()
}

fn main() {
    let m1: Message = "e080fdcf43cb23779c2c2a1d00000000000000ac2c40d2f7e3fea0604f02d5f09bfe1213:31b70a353970bcbd33d3dce5cd94ba0022e567d2e4d74e7c53299e91c8fdb8fe460115690a81863636330be1d2e3322736f35eeb8548729b233864b974123ce166a770672c3b2c5ddf243fe2ce973156ebf23f3345696d600ed6d56cc9fb07861cbf711268a234b4caf87121517d37614d1cb5b660b3f28b2c9b9775cf3a8378d4d8dc034114edec6ce4aef542f6c0c873a2e97dc1d9d2f275856a1ffdc4f6a182675a0dd5d8e3e14bba7b50"
    .parse().unwrap();
    let m2: Message = "e080fdcf43cb23779c2c2a1d00000000000000a23906f30152e4502a5184842c79bf7e56:29b701731e7caabd33f8c5ffdad1e3411ff06fd3e4cb442e556ad099ceafbcad411c116e0a979731253a47ae9edb7a3173e210fd871163812e7779fc7b0637e134bb3e343d36245ddb3970f4c4d42955b7b9132b473b727807c8d76e9ae404905bec301b63ed19b3d3f3712b4729726e5c48f0f37da2fe812388de6ec97fcc7e95dbc1504c1be2a93ae2b3f154f3c0d838a2c67ac69c93ff77c13e04f58bebbc8d21"
    .parse().unwrap();
    let m3: Message = "e080fdcf43cb23779c2c2a1d000000000000009b97db79647070658ae5b282d82fe13cb6:3ebd1c715b6bb1b17bdcc8e4989484156be222c4a1c55339432e9999c6afa1b11201156b4fd6907e29335fe8d7e1757427ef1fead21b3397286c7ffc661227e72de87f293c733a18cc2322f38fd40c5fa8b717274569347807cccf2b9dfe058c57bb345570a822f185f2342d44343c68094bf1e27bf6e38a2d8fd221cb3ec477cc96ce155b1ce0e02fe6b5f15df4d68336cce174cd8ddeff6bc03f"
    .parse().unwrap();

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
        .ok_or("Failed to find h and y0")
        .unwrap();

    let nonce = m1.associated_data[..12].try_into().unwrap();
    let ciphertext = hex::decode("3ebb05705b72bbb167d1ccb6dfd8ac06").unwrap();

    let mini_header = create_mini_header(nonce, &ciphertext);
    let tag = create_tag(h, y0, &mini_header, &ciphertext);

    println!(
        "{}{}:{}",
        hex::encode(mini_header),
        hex::encode(tag),
        hex::encode(ciphertext)
    );
}
