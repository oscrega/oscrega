from numeros import obtener_numeros, suma_numeros_pares, suma_numeros_impares

def main():
    # Obtener lista de números
    lista_numeros = obtener_numeros()
    print("Los números ingresados son:", lista_numeros)

    # Calcular suma de pares e impares
    suma_pares = suma_numeros_pares(lista_numeros)
    suma_impares = suma_numeros_impares(lista_numeros)

    # Escribir en consola el resultado de cada función llamando a la variable que la contiene
    print(f'La suma de los números pares es: {suma_pares}')
    print(f'La suma de los números impares es: {suma_impares}')

# Función que remplaza name por main para poder unir los dos archivos python
if __name__ == "__main__":
    main()
