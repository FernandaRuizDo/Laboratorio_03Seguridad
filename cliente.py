import socket
from os import urandom
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def cifrar(clave, texto_plano, algoritmo):
    # Crear un cifrador con la clave y el modo ECB 
    cifrador = algoritmo.new(clave, algoritmo.MODE_ECB)
    # Aplicar padding al texto plano según el bloque del algoritmo seleccionado
    if algoritmo == DES:
        texto_plano = pad(texto_plano, DES.block_size)
    elif algoritmo == DES3:
        texto_plano = pad(texto_plano, DES3.block_size)
    elif algoritmo == AES:
        texto_plano = pad(texto_plano, AES.block_size)
    
    # Encriptar el texto plano
    texto_cifrado = cifrador.encrypt(texto_plano)
    return texto_cifrado

def generar_clave_diffie_hellman(socket_cliente):
    # Parámetros del algoritmo Diffie-Hellman
    p = 23
    g = 5
    a = 6
    
    # Calcular A y enviarlo al servidor
    A = (g**a) % p
    socket_cliente.send(str(A).encode())
    
    # Recibir B desde el servidor
    B = int(socket_cliente.recv(1024).decode())
    
    # Calcular la clave compartida
    clave_compartida = (B**a) % p
    return str(clave_compartida).encode()

def main(algoritmo, longitud_clave):
    # Crear un socket para el cliente
    socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Conectar al servidor en el puerto 12345
    socket_cliente.connect(('localhost', 12345))

    # Realizar el intercambio de claves Diffie-Hellman
    clave_diffie_hellman = generar_clave_diffie_hellman(socket_cliente)
    print(f"Clave Diffie-Hellman: {clave_diffie_hellman}")

    # Enviar al servidor el nombre del algoritmo seleccionado por el cliente
    socket_cliente.send(algoritmo.__name__.encode())

    # Generar una clave secreta aleatoria para el cifrado seleccionado
    clave = get_random_bytes(longitud_clave)

    # Enviar la clave al servidor
    socket_cliente.send(clave)

    # Leer el mensaje desde el archivo 'mensajeentrada.txt'
    with open('mensajeentrada.txt', 'rb') as archivo:
        mensaje = archivo.read()

    # Encriptar el mensaje utilizando el algoritmo seleccionado y la clave
    mensaje_encriptado = cifrar(clave, mensaje, algoritmo)

    # Enviar el mensaje encriptado al servidor
    socket_cliente.send(mensaje_encriptado)

    print("Mensaje encriptado enviado al servidor")

    # Cerrar el socket del cliente
    socket_cliente.close()

# Permitir al cliente elegir el algoritmo
print("Seleccione el algoritmo (1: DES, 2: 3DES, 3: AES):")
opcion = int(input())

if opcion == 1:
    main(DES, 8)
elif opcion == 2:
    main(DES3, 16)
elif opcion == 3:
    main(AES, 16)
else:
    print("Opción no válida")
