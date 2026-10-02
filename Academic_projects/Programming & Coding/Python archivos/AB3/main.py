import re
from estudiante import Estudiante, Escuela

def limpiar_nombre(nombre):
    return re.sub(r'[^A-Za-záéíóúÁÉÍÓÚüÜñÑ ]', '', str(nombre).strip())

def limpiar_edad(edad):
    numeros = re.sub(r'\D', '', str(edad))
    return int(numeros) if numeros else None

def limpiar_texto(texto):
    texto_limpio = re.sub(r'[^A-Za-záéíóúÁÉÍÓÚüÜñÑ ]', '', str(texto).strip())
    return texto_limpio if texto_limpio else "Campo sin rellenar"

def limpiar_curso(curso):
    curso_limpio = re.sub(r'[^A-Za-z0-9áéíóúÁÉÍÓÚüÜñÑ ]', '', str(curso).strip())
    return curso_limpio

def obtener_nombre_valido(nombre_raw):
    while True:
        nombre_limpio = limpiar_nombre(nombre_raw)
        if nombre_limpio:
            return nombre_limpio
        nombre_raw = input("Por favor, el campo 'nombre' es obligatorio, rellénalo: ")

def obtener_edad_valida(edad_raw):
    while True:
        edad_limpia = limpiar_edad(edad_raw)
        if edad_limpia and edad_limpia > 0:
            return edad_limpia
        edad_raw = input("Por favor, el campo 'edad' es obligatorio, rellénalo (número entero positivo): ")

def obtener_curso_valido(curso_raw, estudiante):
    while True:
        curso_limpio = limpiar_curso(curso_raw)
        if curso_limpio:
            return curso_limpio
        curso_raw = input(f"La clase asignada al estudiante {estudiante} está incompleta, por favor, rellénela: ")

def obtener_promedio_valido(promedio_raw):
    """Si es float válido devuelve float, sino devuelve 'Promedio sin asignar'"""
    try:
        return float(promedio_raw)
    except:
        return "Promedio sin asignar"

def obtener_activo_valido(activo_raw, estudiante):
    while True:
        if isinstance(activo_raw, bool):
            return activo_raw
        elif str(activo_raw).strip().lower() == "true":
            return True
        elif str(activo_raw).strip().lower() == "false":
            return False
        activo_raw = input(f"El campo 'activo' del estudiante {estudiante} es incorrecto o está incompleto, "
                           "por favor, introduzca solo los valores permitidos (True / False): ")

def main():
    datos_estudiantes = [
        ("Rafa Gamero", "18", "Madrid", "programar", "Python 101", 7.3, True),  # Campos incompletos
        ("Ana López", "21", "Barcelona", "leer", "Matemáticas101", 8.7, True),
        ("Luis Pérez", "25", "Valencia", "correr", "Historia201", 7.5, False),
        ("María García", "19", "Sevilla", "dibujar", "Física101", 9.0, True),
        ("Carlos Ruiz", "30", "Bilbao", "cocinar", "Química101", 6.8, False),
        ("Laura Sánchez", "23", "Granada", "viajar", "Literatura101", 8.2, True),
        ("Jorge Martín", "28", "Zaragoza", "fotografía", "Arte101", 9.1, True),
        ("Elena Torres", "20", "Salamanca", "escribir", "Biología101", 7.9, True),
        ("Pablo Díaz", "26", "Oviedo", "tocar la guitarra", "Música101", 8.5, True),
        ("Lucía Romero", "22", "Córdoba", "bailar", "EducaciónFísica101", 9.3, True)
    ]

    estudiantes = []

    for datos in datos_estudiantes:
        nombre = obtener_nombre_valido(datos[0])
        edad = obtener_edad_valida(datos[1])
        ciudad = limpiar_texto(datos[2] if len(datos) > 2 else "")
        hobby = limpiar_texto(datos[3] if len(datos) > 3 else "")

        curso = obtener_curso_valido(datos[4] if len(datos) > 4 else "", nombre)
        promedio = obtener_promedio_valido(datos[5] if len(datos) > 5 else "")
        activo = obtener_activo_valido(datos[6] if len(datos) > 6 else "", nombre)

        estudiante = Estudiante(nombre, edad, ciudad, hobby, curso, promedio, activo)
        estudiantes.append(estudiante)

    # Crear escuela y agregar estudiantes
    escuela = Escuela("Escuela Python", "Madrid")
    for est in estudiantes:
        escuela.agregar_estudiante(est)

    # SALUDOS
    print('\n' + 100*"-" + '\n' + "--> SALUDAR A TODOS LOS ESTUDIANTES" + '\n' + 100*"-", '\n')
    for est in estudiantes:
        est.saludar()

    # PRESENTACIÓN
    print('\n' + 100*"-" + '\n' + "--> PRESENTACIÓN DE TODOS LOS ESTUDIANTES" + '\n' + 100*"-", '\n')
    for est in estudiantes:
        est.presentarse()


    # Métodos nuevos pedidos en el AB3


    # MOSTRAR ESTUDIANTES DE LA ESCUELA
    print('\n' + 100*"-" + '\n' + "--> INFORMACIÓN COMPLETA DE TODOS LOS ESTUDIANTES" + '\n' + 100*"-", '\n')
    escuela.mostrar_estudiantes()

    # MOSTRAR ESTUDIANTES ACTIVOS
    print('\n' + 100*"-" + '\n' + "--> ESTUDIANTES ACTIVOS" + '\n' + 100*"-", '\n')
    escuela.mostrar_estudiantes_activos()


if __name__ == "__main__":
    main()

  
