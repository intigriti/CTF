def encode():
    file_bits_count = len(file_bytes) * 8
    file_bit_index = 0
    chess_board = Board()
    output_pgns = []

    while file_bit_index < file_bits_count:
        legal_moves = list(chess_board.generate_legal_moves())
        max_binary_length = min(
            int(log2(len(legal_moves))), file_bits_count - file_bit_index)

        move_bits = {move.uci(): to_binary_string(i, max_binary_length)
                     for i, move in enumerate(legal_moves)}

        byte_index = file_bit_index // 8
        file_chunk = "".join(to_binary_string(byte, 8)
                             for byte in file_bytes[byte_index: byte_index + 2])
        next_chunk = file_chunk[file_bit_index %
                                8: file_bit_index % 8 + max_binary_length]

        for move_uci, move_binary in move_bits.items():
            if move_binary == next_chunk:
                chess_board.push_uci(move_uci)
                break

        file_bit_index += max_binary_length

        if chess_board.legal_moves.count() <= 1 or chess_board.is_insufficient_material() \
           or chess_board.can_claim_draw():
            pgn_board = pgn.Game()
            pgn_board.add_line(chess_board.move_stack)
            output_pgns.append(str(pgn_board))
            chess_board.reset()
