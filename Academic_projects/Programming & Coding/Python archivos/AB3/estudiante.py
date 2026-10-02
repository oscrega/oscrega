class Estudiante:
    def __init__(self, nombre, edad, ciudad, hobby, curso="Sin asignar", promedio=0.0, activo=True):
        # Validaciones de datos obligatorias para el manejo y entendimiento de errores en el programa
        if not isinstance(nombre, str) or nombre.strip() == "":
            raise ValueError("El nombre debe ser un texto no vacío")
        if not isinstance(edad, int) or edad <= 0:
            raise ValueError("La edad debe ser un número entero positivo")
        if not isinstance(ciudad, str) or ciudad.strip() == "":
            ciudad = "Campo sin rellenar"
        if not isinstance(hobby, str) or hobby.strip() == "":
            hobby = "Campo sin rellenar"

        # Si el atributo curso no es un string o esta vacío se definirá por defecto como "Sin asignar"
        if not isinstance(curso, str) or curso.strip() == "":
            curso = "Sin asignar"
        try: # Calcular el promedio de notas, en caso de no poder calcularlo definir por defecto "0", en caso de no poder definirlo se definira el string "Promedio sin asignar"
            promedio = float(promedio)
            if promedio < 0:
                promedio = 0.0
        except:
            promedio = "Promedio sin asignar"
        if not isinstance(activo, bool):
            activo = True

        self.nombre = nombre
        self.edad = edad
        self.ciudad = ciudad
        self.hobby = hobby
        self.curso = curso
        self.promedio = promedio
        self.activo = activo

    # Método saludar a estudiantes
    def saludar(self):
        print(f"Hola {self.nombre}, ¡Bienvenido/a!")

    # Método los estudiantes se presentan
    def presentarse(self):
        print(
            f"Hola, soy {self.nombre}. "
            f"Tengo {self.edad} años, "
            f"vivo en {self.ciudad} "
            f"y me gusta {self.hobby}."
        )
    
    # Método para mostrar toda la información del estudiante
    def informacion_completa(self):
        print(f"{self.nombre}, Edad: {self.edad}, Ciudad: {self.ciudad}, Hobby: {self.hobby}, "
              f"Curso: {self.curso}, Promedio: {self.promedio}, Activo: {self.activo}")

# Definición de la clase escuela

class Escuela:
    def __init__(self, nombre, ciudad):
        self.nombre = nombre
        self.ciudad = ciudad
        self.estudiantes = []

    def agregar_estudiante(self, estudiante):
        if isinstance(estudiante, Estudiante):
            self.estudiantes.append(estudiante)

    def mostrar_estudiantes(self):
        for e in self.estudiantes:
            e.informacion_completa()

# Método que muestra únicamente los estudiantes que estan activos
    def mostrar_estudiantes_activos(self):
        for e in self.estudiantes:
            if e.activo:
                e.informacion_completa()
