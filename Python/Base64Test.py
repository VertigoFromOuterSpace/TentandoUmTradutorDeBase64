import base64
import os
import re
import binascii

# Espaço para eu colocar os dados lá do wireshark.
dados_base64 = """

"""
# Só verificar os caracteres e matar eles se necessário.

dados_base64_limpo = re.sub(r'^[^A-Za-z0-9+/=]*', '', dados_base64)
dados_base64_limpo = re.sub(r'[^A-Za-z0-9+/=]', '', dados_base64_limpo)

# Base 64 tem que ser múltiplo de 4, então isso daqui vai ser pra verificar se precisa de padding ( ele é feito com o igual =).
if len(dados_base64_limpo) % 4 != 0: 
    padding_needed = 4 - (len(dados_base64_limpo) % 4)
    dados_base64_limpo += '=' * padding_needed

# Tentar decodificar a bomba.
try:
    dados_brutos = base64.b64decode(dados_base64_limpo, validate=True)
    print(f"Base64 válido! Tamanho decodificado: {len(dados_brutos)} bytes")
    
    # Salva no arquivo do output.bin, não fiz tratamento de diretório algum, então ele sempre vai pra pasta root.
    with open("output.bin", "wb") as f:
        f.write(dados_brutos)
    
    print(f"Arquivo salvo em: {os.path.abspath('output.bin')}")
    
    # Analisar os primeiros bytes
    hex_header = binascii.hexlify(dados_brutos[:8]).decode('utf-8')
    print(f"Cabeçalho hexadecimal: {hex_header}")
    
    # Tentar identificar o tipo
    if dados_brutos.startswith(b'\x89PNG'):
        print("Tipo: Imagem PNG")
    elif dados_brutos.startswith(b'\xFF\xD8\xFF'):
        print("Tipo: Imagem JPEG")
    elif dados_brutos.startswith(b'%PDF'):
        print("Tipo: Documento PDF")
    elif dados_brutos.startswith(b'PK\x03\x04'):
        print("Tipo: Arquivo ZIP (pode ser DOCX, XLSX, etc.)")
    elif b"HTTP/1.1" in dados_brutos:
        print("Tipo: Tráfego HTTP contendo texto")
    else:
        print("Tipo: Binário não identificado - Analise com editor hexadecimal")

# Avisar se deu merda, que é sempre importante.
except binascii.Error as e:
    print(f"Erro na decodificação Base64: {e}")
    print("Prováveis problemas:")
    print("- Caracteres inválidos remanescentes")
    print("- Formatação incorreta")
    print(f"String usada (início): {dados_base64_limpo[:100]}...")
    print(f"Tamanho: {len(dados_base64_limpo)} caracteres")
except Exception as e:
    print(f"Erro inesperado: {e}")