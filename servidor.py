import socket
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

def cifrar(clave, texto_cifrado, algoritmo):
    # Crear un cifrador con la clave y el modo ECB 
    cifrador = algoritmo.new(clave, algoritmo.MODE_ECB)
    # Descifrar el texto cifrado
    texto_plano = cifrador.decrypt(texto_cifrado)
    # Quitar el relleno (padding) al texto plano
    return unpad(texto_plano, algoritmo.block_size)

def generar_clave_diffie_hellman(socket_cliente):
    # Parámetros del algoritmo Diffie-Hellman
    p = 23
    g = 5
    b = 15
    # Calcular B y enviarlo al cliente
    B = (g ** b) % p
    A = int(socket_cliente.recv(1024).decode())
    socket_cliente.send(str(B).encode())
    # Calcular la clave compartida
    clave_compartida = (A ** b) % p
    # Convertir la clave compartida a bytes y devolverla
    return str(clave_compartida).encode()

def main():
    # Crear un socket para el servidor
    socket_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Asociar el socket al puerto 12345 y escuchar conexiones entrantes
    socket_servidor.bind(('localhost', 12345))
    socket_servidor.listen()

    print("Esperando conexión...")
    # Aceptar la conexión del cliente y obtener el socket del cliente y su dirección
    socket_cliente, direccion = socket_servidor.accept()
    print(f"Conexión establecida con {direccion}")

    # Realizar el intercambio de claves Diffie-Hellman
    clave_diffie_hellman = generar_clave_diffie_hellman(socket_cliente)
    print(f"Clave Diffie-Hellman: {clave_diffie_hellman}")

    # Recibir el algoritmo seleccionado por el cliente
    algoritmo_nombre = socket_cliente.recv(1024).decode()

    # Configurar el algoritmo y la longitud de la clave según la elección del cliente
    if algoritmo_nombre == DES.__name__:
        algoritmo = DES
        longitud_clave = 8
    elif algoritmo_nombre == DES3.__name__:
        algoritmo = DES3
        longitud_clave = 16
    elif algoritmo_nombre == AES.__name__:
        algoritmo = AES
        longitud_clave = 16
    else:
        print("Algoritmo no válido")
        socket_cliente.close()
        socket_servidor.close()
        return

    # Recibir la clave del cliente
    clave = socket_cliente.recv(longitud_clave)

    # Recibir el mensaje encriptado desde el cliente
    mensaje_encriptado = socket_cliente.recv(1024)

    # Desencriptar el mensaje utilizando el algoritmo seleccionado y la clave
    mensaje_desencriptado = cifrar(clave, mensaje_encriptado, algoritmo)
    print(f"Mensaje desencriptado: {mensaje_desencriptado}")

    # Guardar el mensaje desencriptado en el archivo 'mensajerecibido.txt'
    with open('mensajerecibido.txt', 'wb') as archivo:
        archivo.write(mensaje_desencriptado)

    print("Mensaje desencriptado y guardado en 'mensajerecibido.txt'")

    # Cerrar los sockets del cliente y del servidor
    socket_cliente.close()
    socket_servidor.close()

# Llamar a la función principal
main()
