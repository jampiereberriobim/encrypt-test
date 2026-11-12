import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from .exceptions import ConfigurationError
 
def load_public_key(pem):
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in (2048, 3072, 4096):
        raise ConfigurationError("RSA_2048_3072_4096_REQUIRED")
    if key.public_numbers().e != 65537:
        raise ConfigurationError("RSA_EXPONENT_65537_REQUIRED")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, "SHA256:" + hashlib.sha256(der).hexdigest()
 
def wrap_dek(key, dek):
    if len(dek) != 32:
        raise ConfigurationError("DEK_LENGTH")
    return key.encrypt(bytes(dek), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
     
def encrypt(source, target, dek, wrapped_dek, plain_bytes, chunk_bytes, identities):
    header = {
        "version": 2, "format": "AES_GCM_CHUNKED_V2",
        "algorithm": "AES-256-GCM", "wrap": "RSA-OAEP-SHA256-MGF1",
        "nonce_prefix": base64.b64encode(os.urandom(8)).decode("ascii"),
        "chunk_bytes": chunk_bytes, "plain_bytes": plain_bytes,
        "wrapped_dek_sha256": hashlib.sha256(wrapped_dek).hexdigest(),
        "source_company": identities["source_company"],
        "target_company": identities["target_company"],
    }
    _validate(header, plain_bytes)
    raw = canonical(header)
    if len(raw) > MAX_HEADER:
        raise FormatError("HEADER_TOO_LARGE")
    prefix = MAGIC + struct.pack(">I", len(raw)) + raw
    target.write(prefix)
    binding = hashlib.sha256(prefix).digest()
    nonce = base64.b64decode(header["nonce_prefix"])
    aes = AESGCM(bytes(dek))
    remaining, index = plain_bytes, 0
    digest = hashlib.sha256()
    while remaining:
        part = exact(source, min(chunk_bytes, remaining))
        digest.update(part)
        seq = struct.pack(">I", index)
        target.write(aes.encrypt(nonce + seq, part, binding + seq + b"\x00"))
        remaining -= len(part)
        index += 1
    if source.read(1):
        raise IntegrityError("SOURCE_SIZE_CHANGED")
    seq = struct.pack(">I", index)
    target.write(aes.encrypt(nonce + seq, b"", binding + seq + b"\x01"))
    return {"original_file_sha256": digest.hexdigest(), "plain_bytes": plain_bytes,
            "file_encryption_format": header["format"]}

import argparse
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .crypto_aes_gcm import encrypt
from .crypto_rsa_oaep import load_public_key, wrap_dek

def cifrar_envio(
    origen, clave_publica, salida, empresa_origen, empresa_destino, chunk_bytes
):
    if chunk_bytes <= 0:
        raise ValueError("El tamaño de bloque debe ser mayor que cero.")
    if salida.exists():
        raise FileExistsError(f"La carpeta de salida ya existe: {salida}")
    public_key, _ = load_public_key(clave_publica.read_bytes())
    if public_key.key_size != 4096:
        raise ValueError("La clave pública de Compartamos debe ser RSA de 4096 bits.")
    dek = AESGCM.generate_key(bit_length=256)
    wrapped_dek = wrap_dek(public_key, dek)
    identities = {"source_company": empresa_origen, "target_company": empresa_destino}
    nombre_cifrado = f"{origen.name}.enc"
    nombre_dek = f"{origen.name}.dek"
    salida.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=salida.parent, prefix=".cifrado-") as temporal:
        paquete = Path(temporal) / "envio"
        paquete.mkdir()
        with origen.open("rb") as source, (paquete / nombre_cifrado).open("wb") as target:
            resultado = encrypt(
                source=source,
                target=target,
                dek=dek,
                wrapped_dek=wrapped_dek,
                plain_bytes=os.fstat(source.fileno()).st_size,
                chunk_bytes=chunk_bytes,
                identities=identities,
            )
        (paquete / nombre_dek).write_bytes(wrapped_dek)
        paquete.rename(salida)
    return salida / nombre_cifrado, salida / nombre_dek, resultado
def main():
    parser = argparse.ArgumentParser(description="Cifra un archivo para Compartamos.")
    parser.add_argument("--archivo", type=Path, required=True)
    parser.add_argument("--clave-publica", type=Path, required=True)
    parser.add_argument("--salida", type=Path, required=True, help="Carpeta nueva del envío.")
    parser.add_argument("--empresa-origen", required=True)
    parser.add_argument("--empresa-destino", required=True)
    parser.add_argument("--chunk-bytes", type=int, required=True)
    args = parser.parse_args()
    archivo_cifrado, archivo_dek, resultado = cifrar_envio(
        origen=args.archivo,
        clave_publica=args.clave_publica,
        salida=args.salida,
        empresa_origen=args.empresa_origen,
        empresa_destino=args.empresa_destino,
        chunk_bytes=args.chunk_bytes,
    )
    print(f"Archivo cifrado: {archivo_cifrado}")
    print(f"DEK cifrada: {archivo_dek}")
    print(f"SHA-256 del original: {resultado['original_file_sha256']}")
if __name__ == "__main__":
    main()


#args.clave_publica  --< ES LA QUE YTO TENGO es una llave publica
# codigo para ejecutar . python -m job_encriptacion.cifrar_envio_compartamos --archivo reporte.csv --clave-publica compartamos_dev_publica.pem --salida envio_dev --empresa-origen BIM --empresa-destino COMPARTAMOS --chunk-bytes 1048576

