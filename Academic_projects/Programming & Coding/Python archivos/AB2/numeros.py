def obtener_numeros():
    lista_numeros = []
    secuencia_numeros_enteros = input('Introduce una secuencia de números enteros separados por espacios:\n')

    # Limpiar la entrada de espacios extra
    secuencia_numeros_enteros = secuencia_numeros_enteros.strip()

    for caracter in secuencia_numeros_enteros.split():
        try:
            numero = int(caracter)
            lista_numeros.append(numero)
        except ValueError:
            print(f"'{caracter}' no es un número entero.")
            pregunta_cambio_numero = input(f"¿Deseas cambiarlo por otro número? (sí/no): ").strip().lower()

            if pregunta_cambio_numero in ('sí', 'si'):
                pregunta_numero_nuevo = input('Introduce solamente un nuevo número: ').strip()
                try:
                    numero_nuevo = int(pregunta_numero_nuevo)
                    lista_numeros.append(numero_nuevo)
                    print(f"'{caracter}' ha sido reemplazado por {numero_nuevo}.")
                except ValueError:
                    print(f"El valor introducido ({pregunta_numero_nuevo}) no es un número válido y será ignorado.")
            elif pregunta_cambio_numero == 'no':
                print(f"El valor '{caracter}' será ignorado.")
            else:
                print(f"Respuesta no válida. El valor '{caracter}' será ignorado.")

    return lista_numeros


def suma_numeros_pares(lista_numeros):
    numeros_pares = [num for num in lista_numeros if num % 2 == 0]
    return sum(numeros_pares)


def suma_numeros_impares(lista_numeros):
    numeros_impares = [num for num in lista_numeros if num % 2 != 0]
    return sum(numeros_impares)
