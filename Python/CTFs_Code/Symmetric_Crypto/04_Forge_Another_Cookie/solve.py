import pandas as pd

# Dati: ciphertext intero fornito dall'utente
cipher_int = 13858223270311644019150918694059135423324574766018771785496768672850016251073628095082795455005829015176073744167595



# Conversione in bytes e suddivisione in blocchi da 16 byte
byte_len = (cipher_int.bit_length() + 7) // 8
cipher_bytes = cipher_int.to_bytes(byte_len, 'big')
blocks = [cipher_bytes[i:i+16] for i in range(0, len(cipher_bytes), 16)]

# Preparazione dei dati
data = []
for idx, blk in enumerate(blocks):
    data.append({
        "block": idx,
        "hex": blk.hex(),
        "int_value": int.from_bytes(blk, 'big')
    })

# Visualizza come tabella
df = pd.DataFrame(data)
print(df)